#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors.
# Licensed under the Apache License, Version 2.0.
"""Exercise protected host I/O and fatal entropy failures with real WASM."""
import argparse
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
import time
from wasm_interop import ROOT


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('assets','fixtures','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();out=a.output.resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False);os.umask(0o077)
    cases=json.loads((a.fixtures/'fixtures.json').read_text())['cases']
    c=cases[0]
    state=out/'state-dir';state.mkdir(mode=0o700);sf=state/'state';sf.write_text('UWVM-WSEA-STATE-1\n0 0 -\n');sf.chmod(0o600)
    policy=out/'policy';pb=c['policy'].replace('@STATE_DIR@',str(state));policy.write_text(pb)
    argv=['python3',str(ROOT/'wasm/run.py'),'--runtime','node','--assets',str(a.assets.resolve()),'verify',c['module'],'--policy',str(policy)]
    records=[]
    def run(name,allow=False,args=None,env=None):
        result=subprocess.run(args or argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60,env=env)
        if (result.returncode==0)!=allow:raise RuntimeError(f'{name}: rc={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}')
        if allow and json.loads(result.stdout)['status']!='VERIFIED':raise RuntimeError('invalid host success')
        records.append(name);print('PASS',name,flush=True)
    run('protected positive',True)
    policy.chmod(0o660);run('group-writable policy');policy.chmod(0o600)
    link=out/'symlink';link.symlink_to(policy);run('symlink policy',args=argv[:-1]+[str(link)])
    hard=out/'hardlink';os.link(policy,hard);run('hard-linked policy');hard.unlink()
    sf.chmod(0o640);run('nonprivate state');sf.chmod(0o600)
    saved=sf.read_bytes();sf.unlink();run('missing state is not bootstrapped');assert not sf.exists();sf.write_bytes(saved)
    sf.write_bytes(saved[:-1]);run('truncated state');sf.write_bytes(saved)
    marker=state/('revoked-'+c['pki']['pin']);marker.write_bytes(b'');run('partial permanent revocation record');marker.unlink()
    bad=out/'mutable';bad.mkdir(mode=0o770);bad.chmod(0o770);(bad/'policy').write_text(pb)
    run('group-writable ancestor',args=argv[:-1]+[str(bad/'policy')]);bad.chmod(0o700)
    injection=out/'injection.cjs';flag=out/'injected';injection.write_text('require("node:fs").writeFileSync('+json.dumps(str(flag))+',"bad")')
    run('ambient Node options excluded',True,env=os.environ|{'NODE_OPTIONS':'--require '+str(injection)})
    if flag.exists():raise RuntimeError('ambient code injection was forwarded')
    # A real verifier runs after the authenticated policy snapshot was read.
    # Replacing policy during that window must cause the host to reject it.
    ready=out/'runtime-ready';resume=out/'runtime-resume';engine=out/'delayed-node'
    engine.write_text('#!/usr/bin/python3\nimport os,time\nfrom pathlib import Path\nPath('+repr(str(ready))+').touch()\nwhile not Path('+repr(str(resume))+').exists(): time.sleep(.01)\nos.execv('+repr(shutil.which('node'))+',['+repr(shutil.which('node'))+']+__import__("sys").argv[1:])\n');engine.chmod(0o700)
    def change():
        deadline=time.monotonic()+30
        while not ready.exists():
            if time.monotonic()>deadline:return
            time.sleep(.01)
        policy.write_text(pb.replace('policy_version=1\n','policy_version=2\n'));resume.touch()
    thread=threading.Thread(target=change);thread.start()
    delayed=argv[:4]+['--engine',str(engine)]+argv[4:]
    try:run('policy changed during crypto verification',args=delayed)
    finally:resume.touch();thread.join(timeout=10);policy.write_text(pb)
    if not ready.exists():raise RuntimeError('race test never reached the real runtime')
    # Process starts with actual WASM, then CSPRNG failure occurs at signing.
    b64=lambda b:base64.b64encode(b).decode()
    now=int(time.time());req={'schema':'wsea-sdk-1','operation':'sign','module':b64(bytes.fromhex('0061736d0100000001040160000003020100070a01065f737461727400000a040102000b')),
        'trust':{'policy':b64(pb.encode()),'roots':b64(Path(c['pki']['root']).read_bytes()),'state':b64(saved),'revoked_spkis':[]},
        'signing':{'key':b64(Path(c['pki']['key']).read_bytes()),'certificates':b64(Path(c['pki']['certificate']).read_bytes()),'crls':b64(Path(c['pki']['crl']).read_bytes()),
        'manifest':{'embedded':True,'algorithm':'ES256','module_id':'matrix.app','version':1,'security_epoch':0,'not_before':now-60,'not_after':now+600,'abi':'uwvm2','capabilities':0}}}
    (out/'signing.json').write_text(json.dumps(req))
    js=out/'entropy.mjs';assets=a.assets.resolve()
    js.write_text('''import fs from 'node:fs';
import {pathToFileURL} from 'node:url';
const assets=process.argv[2];
await import(pathToFileURL(assets+'/wasm_exec.js').href);
const {createWsea}=await import(pathToFileURL(assets+'/loader.mjs').href);
const sdk=await createWsea({cryptoBytes:fs.readFileSync(assets+'/wsea-crypto.wasm'),frontendBytes:fs.readFileSync(assets+'/wasm-cosign-js.wasm'),go:new Go()});
Object.defineProperty(globalThis,'crypto',{value:{getRandomValues(){throw new Error('test entropy unavailable')}},configurable:true});
let denied=false;
try { const text=sdk.requestJSON(fs.readFileSync(process.argv[3],'utf8')); denied=JSON.parse(text).status==='REJECTED'; }
catch { denied=true; }
if (!denied) throw new Error('entropy failure accepted');
console.log('ENTROPY_FAILURE_DENIED');
''')
    process=subprocess.run(['node',str(js),str(assets),str(out/'signing.json')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
    (out/'entropy.stderr.log').write_bytes(process.stderr)
    if process.returncode or b'ENTROPY_FAILURE_DENIED' not in process.stdout:raise RuntimeError('CSPRNG failure was not rejected')
    records.append('entropy failure denied')
    rsa=next(case for case in cases if case['name']=='PS256 valid exact profile')
    verify={'schema':'wsea-sdk-1','operation':'verify','module':b64(Path(rsa['module']).read_bytes()),'trust':{
        'policy':b64(rsa['policy'].replace('@STATE_DIR@',str(state)).encode()),'roots':b64(Path(rsa['pki']['root']).read_bytes()),
        'state':b64(saved),'revoked_spkis':[]}}
    (out/'rsa-verification.json').write_text(json.dumps(verify))
    process=subprocess.run(['node',str(js),str(assets),str(out/'rsa-verification.json')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
    (out/'openssl-entropy.stderr.log').write_bytes(process.stderr)
    if process.returncode or b'ENTROPY_FAILURE_DENIED' not in process.stdout:raise RuntimeError('OpenSSL RSA verification entropy failure was not rejected')
    records.append('OpenSSL verification entropy failure denied')
    (out/'results.json').write_text(json.dumps({'status':'PASS','checks':records},indent=2)+'\n')
    print(json.dumps({'status':'PASS','checks':len(records)}),flush=True)


if __name__=='__main__':main()
