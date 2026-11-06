#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors.
# Licensed under the Apache License, Version 2.0.
"""Qualify the exact release source in a disposable, bounded FreeBSD QEMU guest."""
import argparse
import json
import lzma
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import time
from wsea_cross_support import cgroup_snapshot, download, finish_cgroup, private_environment, private_path, sha

IMAGE_URL = 'https://download.freebsd.org/releases/VM-IMAGES/15.1-RELEASE/amd64/Latest/FreeBSD-15.1-RELEASE-amd64-BASIC-CLOUDINIT-ufs.qcow2.xz'
IMAGE_SHA = 'e4ca4db889f8559c9b9dfcacc70405c038476f4b6d41649b152d3809a2ed9e1f'
GO_URL = 'https://go.dev/dl/go1.26.8.freebsd-amd64.tar.gz'
GO_SHA = '458adea37c17ce9a8754a0455fa43e84f27d7e7de3fee81041a13de40c766434'


def snapshot(source, destination, version=None):
    command = ['git', 'clone', '--no-local', '--depth', '1', '--no-checkout']
    if version:
        command += ['--branch', version]
    subprocess.run([*command, str(source), str(destination)], check=True)
    if not version:
        subprocess.run(['git', '-C', str(destination), 'sparse-checkout', 'set', '--cone',
                        'src/uwvm2/utils/security', 'third-parties/openssl', 'tools/dependencies'], check=True)
    subprocess.run(['git', '-C', str(destination), 'checkout', '--detach', 'HEAD'], check=True)
    archive = destination.with_suffix('.tar.gz')
    with tarfile.open(archive, 'w:gz', compresslevel=1) as tar:
        tar.add(destination, arcname='.')
    return archive


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--version', required=True)
    p.add_argument('--source-root', type=Path, required=True)
    p.add_argument('--uwvm-root', type=Path, required=True)
    p.add_argument('--work', type=Path, required=True)
    p.add_argument('--qemu-data', type=Path, help='private QEMU firmware directory, if not installed system-wide')
    p.add_argument('--bios', type=Path, help='explicit SeaBIOS path for a private QEMU installation')
    a = p.parse_args()
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', a.version):
        p.error('explicit immutable semantic release tag required')
    source, counterpart, work = a.source_root.resolve(), a.uwvm_root.resolve(), private_path(a.work)
    work.mkdir(parents=True, exist_ok=False)
    private_environment(work)
    before = cgroup_snapshot()
    product_revision = subprocess.check_output(['git', '-C', str(source), 'rev-parse', a.version + '^{commit}'], text=True).strip()
    expected_partner = (source / 'scripts/wsea_uwvm_revision.txt').read_text().strip()
    for tree, revision in ((source, product_revision), (counterpart, expected_partner)):
        if (subprocess.check_output(['git', '-C', str(tree), 'status', '--porcelain']) or
                subprocess.check_output(['git', '-C', str(tree), 'rev-parse', 'HEAD'], text=True).strip() != revision):
            raise RuntimeError('clean pinned product/counterpart checkout required')
    image = download(IMAGE_URL, IMAGE_SHA, work / 'image.qcow2.xz')
    go = download(GO_URL, GO_SHA, work / 'go.tar.gz')
    with lzma.open(image) as src, (work / 'base.qcow2').open('xb') as dest:
        shutil.copyfileobj(src, dest, 1 << 20)
    subprocess.run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b',
                    str(work / 'base.qcow2'), str(work / 'overlay.qcow2'), '24G'], check=True)
    source_tar = snapshot(source, work / 'source', a.version)
    counterpart_tar = snapshot(counterpart, work / 'uwvm')
    key = work / 'ssh-key'
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
    seed = work / 'seed'
    seed.mkdir()
    setup = ('#!/bin/sh\nset -eu\nsysrc sshd_enable=YES\n'
             'env ASSUME_ALWAYS_YES=yes pkg bootstrap\n'
             'pkg install -y git python3 perl5 pkgconf gmake\ntouch /var/run/wsea-ready\n')
    config = {'hostname': 'wsea-freebsd', 'ssh_pwauth': False,
              'users': [{'name': 'wsea', 'homedir': '/home/wsea', 'shell': '/bin/sh', 'locked': False,
                         'gecos': 'Disposable release builder',
                         'ssh_authorized_keys': [key.with_suffix('.pub').read_text().strip()]}],
              'package_update': False, 'package_upgrade': False,
              'write_files': [
                  {'path': '/etc/rc.conf.d/firstboot_pkg_upgrade', 'owner': 'root:wheel',
                   'permissions': '0600', 'content': 'firstboot_pkg_upgrade_enable="NO"\n'},
                  {'path': '/root/wsea-setup.sh', 'owner': 'root:wheel', 'permissions': '0700', 'content': setup}],
              'runcmd': ['/bin/sh /root/wsea-setup.sh']}
    (seed / 'user-data').write_text('#cloud-config\n' + json.dumps(config, indent=2) + '\n')
    (seed / 'meta-data').write_text('instance-id: wsea-disposable-build\nlocal-hostname: wsea-freebsd\n')
    subprocess.run(['genisoimage', '-quiet', '-output', str(work / 'seed.iso'), '-volid', 'cidata',
                    '-joliet', '-rock', str(seed / 'user-data'), str(seed / 'meta-data')], check=True)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = str(sock.getsockname()[1])
    kvm = os.access('/dev/kvm', os.R_OK | os.W_OK)
    command = ['qemu-system-x86_64', '-machine', 'q35,accel=' + ('kvm' if kvm else 'tcg'),
               '-cpu', 'host' if kvm else 'max', '-smp', '2', '-m', '4096', '-vga', 'none',
               '-drive', 'file=' + str(work / 'overlay.qcow2') + ',if=virtio,format=qcow2',
               '-drive', 'file=' + str(work / 'seed.iso') + ',media=cdrom,format=raw,readonly=on',
               '-netdev', 'user,id=net0,hostfwd=tcp:127.0.0.1:' + port + '-:22',
               '-device', 'virtio-net-pci,netdev=net0,romfile=', '-display', 'none', '-monitor', 'none',
               '-serial', 'file:' + str(work / 'serial.log')]
    if a.qemu_data:
        command += ['-L', str(a.qemu_data.resolve())]
    if a.bios:
        command += ['-bios', str(a.bios.resolve())]
    options = ['-i', str(key), '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=accept-new',
               '-o', 'UserKnownHostsFile=' + str(work / 'known_hosts'), '-o', 'ConnectTimeout=5']
    ssh = ['ssh', *options, '-p', port, 'wsea@127.0.0.1']
    scp = ['scp', *options, '-P', port]
    with (work / 'qemu.log').open('w') as log:
        vm = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 900
            while time.monotonic() < deadline:
                if vm.poll() is not None:
                    raise RuntimeError('FreeBSD QEMU exited; inspect private qemu.log')
                result = subprocess.run([*ssh, 'test -f /var/run/wsea-ready'], capture_output=True, timeout=15)
                if result.returncode == 0:
                    break
                print('Waiting for FreeBSD first-boot prerequisites', flush=True)
                time.sleep(10)
            else:
                raise RuntimeError('FreeBSD prerequisites did not become ready')
            for file, name in ((source_tar, 'source.tar.gz'), (counterpart_tar, 'uwvm.tar.gz'), (go, 'go.tar.gz')):
                subprocess.run([*scp, str(file), 'wsea@127.0.0.1:/home/wsea/' + name], check=True, timeout=180)
            guest = '/home/wsea/wasm-cosign'
            script = f'''#!/bin/sh
set -eu
umask 077
ulimit -c 0
mkdir -p {guest}
tar -xzf /home/wsea/source.tar.gz -C {guest}
mkdir -p {guest}/.tmp/uwvm {guest}/.tmp/tools/bin {guest}/.tmp/tmp
tar -xzf /home/wsea/uwvm.tar.gz -C {guest}/.tmp/uwvm
tar -xzf /home/wsea/go.tar.gz -C {guest}/.tmp/tools
cd {guest}
ln -s /usr/local/bin/gmake .tmp/tools/bin/make
export PATH="{guest}/.tmp/tools/bin:{guest}/.tmp/tools/go/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export TMPDIR="{guest}/.tmp/tmp" GOTMPDIR="{guest}/.tmp/tmp"
export GOCACHE="{guest}/.tmp/go-cache" GOMODCACHE="{guest}/.tmp/go-modules"
export UWVM2_ROOT="{guest}/.tmp/uwvm" GOMAXPROCS=2 WSEA_OPENSSL_JOBS=2
export GOTOOLCHAIN=local GOENV=off PYTHONDONTWRITEBYTECODE=1
test "$(git rev-parse HEAD)" = {product_revision}
test "$(git -C .tmp/uwvm rev-parse HEAD)" = {expected_partner}
go version
uname -a
python3 scripts/build_wsea_release.py --version {a.version} --target x86_64-freebsd15 --work .tmp/native/build --output .tmp/native/assets
mkdir .tmp/native/extracted
tar -xJf .tmp/native/assets/x86_64-freebsd15-wasm-cosign-{a.version}.tar.xz -C .tmp/native/extracted
.tmp/native/extracted/x86_64-freebsd15-wasm-cosign-{a.version}/cosign version
'''
            script_path = work / 'build.sh'
            script_path.write_text(script)
            subprocess.run([*scp, str(script_path), 'wsea@127.0.0.1:/home/wsea/build.sh'], check=True)
            with (work / 'build.log').open('w') as build_log:
                subprocess.run([*ssh, '/bin/sh /home/wsea/build.sh'], stdout=build_log,
                               stderr=subprocess.STDOUT, check=True, timeout=2400)
            assets = work / 'assets'
            assets.mkdir()
            name = 'x86_64-freebsd15-wasm-cosign-' + a.version + '.tar.xz'
            subprocess.run([*scp, 'wsea@127.0.0.1:' + guest + '/.tmp/native/assets/' + name, str(assets / name)], check=True)
            subprocess.run([*scp, 'wsea@127.0.0.1:' + guest + '/.tmp/native/build/product-tests.log',
                            str(work / 'product-tests.log')], check=True)
            finish_cgroup(before, work / 'cgroup.json')
            (work / 'qualification.json').write_text(json.dumps({'status': 'PASS', 'source_revision': product_revision,
                'uwvm_revision': expected_partner, 'archive_sha256': sha(assets / name),
                'image_sha256': IMAGE_SHA, 'go_sha256': GO_SHA, 'acceleration': 'kvm' if kvm else 'tcg'}, indent=2) + '\n')
            print('PASS: actual FreeBSD source build, product tests and packaged executable', flush=True)
        finally:
            vm.terminate()
            try:
                vm.wait(timeout=20)
            except subprocess.TimeoutExpired:
                vm.kill()
                vm.wait()


if __name__ == '__main__':
    main()
