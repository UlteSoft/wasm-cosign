#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors. Apache-2.0.
"""Exercise the real native CLI through the GUI's authenticated HTTP API.

No build step. Generates disposable PKI and reports only below project .tmp.
Optional --uwvm-verifier invokes an existing independent UWVM verifier.
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import server as gui


def cgroup(required):
    if sys.platform!='linux':
        if required:raise RuntimeError('A Linux cgroup is required.')
        return None
    relative=Path('/proc/self/cgroup').read_text().strip().split('0::')[-1]
    path=Path('/sys/fs/cgroup')/relative.lstrip('/')
    if not (path/'memory.max').exists():
        if required:raise RuntimeError('No memory cgroup available.')
        return None
    result={k:(path/k).read_text().strip() for k in ['memory.max','memory.swap.max','memory.events']}
    result['path']=str(path)
    if required and (result['memory.max']=='max' or int(result['memory.max'])>64*1024**3 or result['memory.swap.max']!='0'):
        raise RuntimeError('Tests require a cgroup with memory.max <= 64 GiB and zero swap.')
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',required=True,type=Path)
    p.add_argument('--uwvm-verifier',type=Path)
    p.add_argument('--require-cgroup',action='store_true')
    p.add_argument('--output',type=Path,help='New output directory inside project .tmp')
    a=p.parse_args()
    os.umask(0o077)
    scratch=Path(__file__).resolve().parents[2]/'.tmp'/'webgui'
    scratch.mkdir(mode=0o700,parents=True,exist_ok=True)
    if a.output:
        out=a.output.resolve()
        if scratch.parent not in out.parents:p.error('--output must be inside project .tmp')
        out.mkdir(mode=0o700,parents=True,exist_ok=False)
    else:out=Path(tempfile.mkdtemp(prefix='integration-',dir=scratch))
    os.environ['TMPDIR']=str(out)
    before=cgroup(a.require_cgroup)
    records=[]
    def record(name,passed,**details):
        records.append({'name':name,'passed':bool(passed),**details})
        print(('PASS' if passed else 'FAIL')+' '+name,flush=True)
        if not passed:raise AssertionError(name+' '+str(details))
    def openssl(*args):
        r=subprocess.run(['openssl',*map(str,args)],stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=120)
        if r.returncode:raise RuntimeError(r.stderr)
        return r.stdout
    def make_pki(name,kind,curve=None):
        d=out/name;d.mkdir(mode=0o700);(d/'newcerts').mkdir()
        for f,v in [('index',''),('serial','1000\n'),('crlnumber','1000\n')]: (d/f).write_text(v)
        openssl('genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:prime256v1','-out',d/'root.key')
        openssl('req','-new','-x509','-key',d/'root.key','-out',d/'root.pem','-days','3','-subj','/CN=WSEA GUI test root '+name,'-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-addext','subjectKeyIdentifier=hash')
        opts=['-pkeyopt','ec_paramgen_curve:'+curve] if kind=='EC' else ['-pkeyopt','rsa_keygen_bits:3072'] if kind=='RSA' else []
        openssl('genpkey','-algorithm',kind,*opts,'-out',d/'signer.key')
        openssl('req','-new','-key',d/'signer.key','-out',d/'signer.csr','-subj','/CN=WSEA GUI signer '+name)
        (d/'ca.cnf').write_text(f'''[ca]
default_ca=local
[local]
dir={d}
database=$dir/index
new_certs_dir=$dir/newcerts
certificate=$dir/root.pem
private_key=$dir/root.key
serial=$dir/serial
crlnumber=$dir/crlnumber
default_md=sha256
default_days=2
default_crl_days=1
policy=names
unique_subject=no
x509_extensions=signer
[names]
commonName=supplied
[signer]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=codeSigning
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
''')
        openssl('ca','-batch','-notext','-config',d/'ca.cnf','-in',d/'signer.csr','-out',d/'signer.pem')
        openssl('ca','-batch','-config',d/'ca.cnf','-gencrl','-out',d/'fresh.crl.pem')
        return {'key':str(d/'signer.key'),'certificate':str(d/'signer.pem'),'crl':str(d/'fresh.crl.pem'),'root':str(d/'root.pem')}

    app=None;server=None;tls=None
    old_tls_env={k:os.environ.get(k) for k in ['SSL_CERT_FILE','SSL_CERT_DIR']}
    try:
        app=gui.Application(a.binary,30)
        server=gui.LocalServer(('127.0.0.1',0),app)
        worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
        def request(path,body=None):
            conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=10)
            conn.request('GET' if body is None else 'POST',path,body=None if body is None else json.dumps(body),headers={'Authorization':'Bearer '+app.token,'Origin':server.origin,'Content-Type':'application/json'})
            r=conn.getresponse();raw=r.read();conn.close()
            if r.status not in (200,202):raise AssertionError(str(r.status)+' '+raw.decode())
            assert str(out).encode() not in raw, 'Local path leaked in HTTP response'
            assert b'PRIVATE KEY' not in raw, 'Key data leaked in HTTP response'
            return json.loads(raw)
        def call(name,command,fields,expected='succeeded'):
            public_fields=dict(fields)
            for field,spec in gui.SCHEMAS[command].items():
                if spec.rstrip('!') not in ('path','paths') or not fields.get(field):continue
                paths=fields[field] if spec=='paths' else [fields[field]]
                refs=[app.register_file(path,gui.file_role(command,field))['id'] for path in paths]
                public_fields[field]=refs if spec=='paths' else refs[0]
            job=request('/api/jobs',{'command':command,'fields':public_fields})
            deadline=time.monotonic()+40
            while job['state']=='running':
                if time.monotonic()>deadline:raise RuntimeError('GUI job deadline')
                time.sleep(.025);job=request('/api/jobs/'+job['id'])
            record(name,job['state']==expected,state=job['state'],result=job)
            return job
        for topic in ['sign','verify','fetch','policy-init','policy-update']:
            result=gui.run_bounded([str(a.binary.resolve()),'wasm','secure',topic,'--help'],10)
            flags=set(re.findall(r'--([a-z][a-z-]*)',result['stdout']))-{'help'}
            expected=set(gui.SCHEMAS[topic])-{'module','in-place'}-({'output'} if topic=='fetch' else set())
            record('complete flag coverage '+topic,result['exit_code']==0 and flags==expected,flags=sorted(flags),gui=sorted(expected))
        record('configuration contains no local metadata',set(request('/api/config'))=={'algorithms','active_job','selection','jobs'})
        pki={
            'P256':make_pki('p256','EC','prime256v1'),
            'P384':make_pki('p384','EC','secp384r1'),
            'P521':make_pki('p521','EC','secp521r1'),
            'RSA':make_pki('rsa','RSA'),
            'Ed25519':make_pki('ed25519','ED25519'),
        }
        now=dt.datetime.now(dt.timezone.utc)
        stamp=lambda d:d.strftime('%Y-%m-%dT%H:%M:%SZ')
        times={'not-before':stamp(now-dt.timedelta(minutes=1)),'not-after':stamp(now+dt.timedelta(hours=1))}
        unsigned=out/'unsigned.wasm';unsigned.write_bytes(b'\0asm\x01\0\0\0')
        def signer(alg):
            return pki['Ed25519' if alg=='Ed25519' else 'P'+('256' if alg.endswith('256') else '384' if alg.endswith('384') else '521') if alg.startswith('ES') else 'RSA']
        def policy_fields(d,ca,alg):
            return {'output':str(d/'policy'),'state-dir':str(d/'state'),'trust-root':ca['root'],'certificate':ca['certificate'],'module-id':'gui.test','algorithms':alg,'policy-version':'1','minimum-version':'1','minimum-epoch':'0','capabilities':'0','max-crl-age-seconds':'86400','max-module-bytes':'1048576','signature-threshold':'1'}
        def sign_fields(d,ca,alg,**extra):
            return {'module':str(unsigned),'output':str(d/'signed.wasm'),'policy':str(d/'policy'),**{k:ca[k] for k in ['key','certificate','crl']},'algorithm':alg,'module-id':'gui.test','module-version':'1','security-epoch':'0','capabilities':'0',**times,**extra}
        for alg in gui.ALGORITHMS:
            d=out/alg;d.mkdir();ca=signer(alg)
            call(alg+' policy-init','policy-init',policy_fields(d,ca,alg))
            call(alg+' sign','sign',sign_fields(d,ca,alg))
            call(alg+' verify','verify',{'module':str(d/'signed.wasm'),'policy':str(d/'policy')})
            if a.uwvm_verifier:
                r=subprocess.run([str(a.uwvm_verifier.resolve()),str(d/'policy'),str(d/'signed.wasm')],capture_output=True,text=True,timeout=30)
                record(alg+' UWVM independent verification',r.returncode==0 and r.stdout.strip()=='ALLOW',stdout=r.stdout,stderr=r.stderr)
        d=out/'ES256';ca=pki['P256'];policy=str(d/'policy');original=(d/'signed.wasm').read_bytes()
        call('refuse existing output','sign',sign_fields(d,ca,'ES256'),'failed')
        record('existing output unchanged',(d/'signed.wasm').read_bytes()==original)
        call('explicit replace in place','sign',sign_fields(d,ca,'ES256',module=str(d/'signed.wasm'),output='',**{'in-place':True,'replace-signature':True}))
        bad=out/'not-wasm.txt';bad.write_text('not wasm')
        call('non-WASM sign refused','sign',sign_fields(d,ca,'ES256',module=str(bad),output=str(out/'bad.wasm')),'failed')
        call('non-WASM verify refused','verify',{'module':str(bad),'policy':policy},'failed')
        tampered=out/'tampered.wasm';tampered.write_bytes((d/'signed.wasm').read_bytes()+b'\0')
        call('tampered module refused','verify',{'module':str(tampered),'policy':policy},'failed')
        Path(ca['key']).chmod(0o644)
        try:call('publicly readable key refused','sign',sign_fields(d,ca,'ES256',output=str(out/'insecure-key.wasm')),'failed')
        finally:Path(ca['key']).chmod(0o600)
        m=out/'mixed';m.mkdir();roots=m/'roots.pem';roots.write_bytes(b''.join(Path(pki[k]['root']).read_bytes() for k in ['P256','RSA','Ed25519']))
        fields=policy_fields(m,pki['P256'],'ES256,RS256,Ed25519')|{'trust-root':str(roots),'additional-certificate':[pki['RSA']['certificate'],pki['Ed25519']['certificate']],'signature-threshold':'3'}
        call('mixed 3-of-3 policy','policy-init',fields)
        one=m/'one.wasm';two=m/'two.wasm';three=m/'three.wasm'
        call('ECDSA one-of-three partial','sign',sign_fields(m,pki['P256'],'ES256',output=str(one),**{'allow-partial':True}),'partial')
        call('partial cannot verify','verify',{'module':str(one),'policy':str(m/'policy')},'failed')
        duplicate=call('same ECDSA key remains partial','sign',sign_fields(m,pki['P256'],'ES256',module=str(one),output=str(m/'duplicate.wasm'),**{'append-signature':True,'allow-partial':True}),'partial')
        record('same key does not increase quorum',duplicate['document']['manifest']['signer_count']==1)
        call('same-key contributions cannot satisfy quorum','verify',{'module':str(m/'duplicate.wasm'),'policy':str(m/'policy')},'failed')
        call('mismatched manifest refused','sign',sign_fields(m,pki['RSA'],'RS256',module=str(one),output=str(two),**{'append-signature':True,'allow-partial':True,'module-version':'2'}),'failed')
        record('failed append did not publish',not two.exists())
        call('RSA two-of-three partial','sign',sign_fields(m,pki['RSA'],'RS256',module=str(one),output=str(two),**{'append-signature':True,'allow-partial':True}),'partial')
        call('two-of-three cannot verify','verify',{'module':str(two),'policy':str(m/'policy')},'failed')
        call('Ed25519 completes quorum','sign',sign_fields(m,pki['Ed25519'],'Ed25519',module=str(two),output=str(three),**{'append-signature':True}))
        j=call('mixed full verification','verify',{'module':str(three),'policy':str(m/'policy')})
        record('three distinct mixed signers',j['document']['manifest']['signer_count']==3 and set(j['document']['manifest']['signature_algorithms'])=={'ES256','RS256','Ed25519'})
        if a.uwvm_verifier:
            for module,allowed in [(one,False),(two,False),(three,True)]:
                r=subprocess.run([str(a.uwvm_verifier.resolve()),str(m/'policy'),str(module)],capture_output=True,text=True,timeout=30)
                record('UWVM mixed '+module.stem,(r.returncode==0 and r.stdout.strip()=='ALLOW') if allowed else r.returncode==2 and r.stdout.startswith('DENY '),stdout=r.stdout,stderr=r.stderr)
        state_before=(m/'state'/'state').read_bytes()
        call('policy no implicit reset','policy-update',{'policy':str(m/'policy'),'policy-version':'2'})
        current=(m/'policy').read_text()
        record('policy update preserves quorum and algorithms',all(a in current for a in ['ES256','RS256','Ed25519']) and current.split('module=')[1].strip().endswith('|3'))
        record('policy update preserves VM state',(m/'state'/'state').read_bytes()==state_before)
        call('non-increasing policy version refused','policy-update',{'policy':str(m/'policy'),'policy-version':'2'},'failed')
        call('mixed version floor update','policy-update',{'policy':str(m/'policy'),'policy-version':'3','module-id':'gui.test','minimum-version':'2'})
        call('same publisher old version refused','verify',{'module':str(three),'policy':str(m/'policy')},'failed')
        call('explicit signer and algorithm rotation','policy-update',{'policy':str(m/'policy'),'policy-version':'4','module-id':'gui.test','trust-root':pki['Ed25519']['root'],'certificate':pki['Ed25519']['certificate'],'clear-additional-signers':True,'signature-threshold':'1','algorithms':'Ed25519','minimum-version':'2','minimum-epoch':'1','capabilities':'0','max-crl-age-seconds':'86400','max-module-bytes':'1048576'})
        call('rotated signer new version','sign',sign_fields(m,pki['Ed25519'],'Ed25519',output=str(m/'rotated.wasm'),**{'module-version':'2','security-epoch':'1'}))
        call('additional signer replacement patch','policy-update',{'policy':str(m/'policy'),'policy-version':'5','module-id':'gui.test','trust-root':str(roots),'additional-certificate':[pki['RSA']['certificate']],'signature-threshold':'2','algorithms':'Ed25519,RS256'})
        call('state reset refused','policy-init',fields,'failed')
        record('policy-init did not reset existing state',(m/'state'/'state').read_bytes()==state_before)
        # Fresh disposable TLS server; trust is set only in this test process.
        tlsdir=out/'tls';tlsdir.mkdir();(tlsdir/'empty-roots').mkdir()
        openssl('genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:prime256v1','-out',tlsdir/'key.pem')
        openssl('req','-new','-key',tlsdir/'key.pem','-out',tlsdir/'server.csr','-subj','/CN=localhost')
        (tlsdir/'extensions').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n')
        openssl('x509','-req','-in',tlsdir/'server.csr','-CA',pki['P256']['root'],'-CAkey',out/'p256'/'root.key','-set_serial','555','-days','1','-extfile',tlsdir/'extensions','-out',tlsdir/'server.pem')
        class HTTPSHandler(BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def do_GET(self):
                if self.path=='/redirect':
                    self.send_response(302);self.send_header('Location','http://127.0.0.1:9/plain');self.end_headers();return
                data=(one if self.path=='/partial' else tampered if self.path=='/tampered' else d/'signed.wasm').read_bytes()
                self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
        tls=ThreadingHTTPServer(('127.0.0.1',0),HTTPSHandler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(tlsdir/'server.pem',tlsdir/'key.pem');tls.socket=context.wrap_socket(tls.socket,server_side=True)
        tlsworker=threading.Thread(target=tls.serve_forever,daemon=True);tlsworker.start()
        url='https://127.0.0.1:'+str(tls.server_port)
        fetch={'policy':policy,'url':url+'/ok','output':str(out/'downloaded.wasm')}
        os.environ['SSL_CERT_FILE']=pki['RSA']['root'];os.environ['SSL_CERT_DIR']=str(tlsdir/'empty-roots')
        call('untrusted TLS certificate refused','fetch',fetch,'failed')
        record('TLS failure did not publish',not (out/'downloaded.wasm').exists())
        os.environ['SSL_CERT_FILE']=pki['P256']['root']
        call('authenticated HTTPS + WSEA fetch','fetch',fetch)
        record('download exact bytes',(out/'downloaded.wasm').read_bytes()==(d/'signed.wasm').read_bytes())
        call('fetch refuses overwrite','fetch',fetch,'failed')
        call('HTTPS downgrade refused','fetch',fetch|{'url':url+'/redirect','output':str(out/'redirect.wasm')},'failed')
        call('tampered HTTPS module refused','fetch',fetch|{'url':url+'/tampered','output':str(out/'tampered-download.wasm')},'failed')
        # Use the original mixed policy parameters, in a new protected state, for partial fetch.
        fresh=out/'partial-fetch';fresh.mkdir()
        call('partial fetch policy','policy-init',fields|{'output':str(fresh/'policy'),'state-dir':str(fresh/'state')})
        call('HTTPS partial quorum refused','fetch',fetch|{'policy':str(fresh/'policy'),'url':url+'/partial','output':str(out/'partial-download.wasm')},'failed')
        # Stable inputs for manual/browser QA; paths only, no key material in JSON.
        (out/'browser-fixture.json').write_text(json.dumps({'sign':sign_fields(d,ca,'ES256',output=str(out/'browser-signed.wasm')),'mixed':fields,'pki':pki,'times':times},indent=2))
    finally:
        if tls:tls.shutdown();tls.server_close()
        if server:server.shutdown();server.server_close()
        for key,old in old_tls_env.items():
            if old is None:os.environ.pop(key,None)
            else:os.environ[key]=old
        after=cgroup(a.require_cgroup)
        if before and after:
            def oom(snapshot):return {k:int(v) for k,v in (line.split() for line in snapshot['memory.events'].splitlines()) if k.startswith('oom')}
            record('64 GiB cgroup has no new OOM events',before['path']==after['path'] and oom(before)==oom(after),before=before,after=after)
        (out/'report.json').write_text(json.dumps({'binary':str(a.binary.resolve()),'binary_sha256':hashlib.sha256(a.binary.read_bytes()).hexdigest(),'checks':records,'passed':sum(r['passed'] for r in records),'total':len(records)},indent=2))
    print('PASS',len(records),'checks;',out,flush=True)


if __name__=='__main__':main()
