#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors.
# Licensed under the Apache License, Version 2.0.
"""Cross-sign all WSEA profiles and mixed-key quorums in real WASM runtimes."""
import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time
from datetime import datetime, timezone
from wasm_interop import Stream, b64, ROOT


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('assets','fixtures','native-verifier','native-cosign','uwvm','output'):
        p.add_argument('--'+name,type=Path,required=True)
    a = p.parse_args()
    out = a.output.resolve(); out.mkdir(mode=0o700, parents=True, exist_ok=False); os.umask(0o077)
    host_spec = importlib.util.spec_from_file_location('wsea_host', ROOT/'wasm/run.py')
    host = importlib.util.module_from_spec(host_spec); host_spec.loader.exec_module(host)
    assets = a.assets.resolve()
    engines = [Stream(name,host.command(name,str(a.uwvm.resolve()) if name=='uwvm' else None,assets)+['--stream'],out)
               for name in ('wasmtime','node','uwvm')]
    # Node stream switch follows the assets positional argument, as in run-json.
    native = Stream('native',[str(a.native_verifier.resolve()),'--batch'],out)
    manifest = json.loads((a.fixtures/'fixtures.json').read_text())
    cases = manifest['cases']; records=[]
    def record(name):
        records.append(name); (out/'results.json').write_text(json.dumps(records,indent=2)+'\n');print('PASS',name,flush=True)
    def context(name, selected, threshold=1):
        d=out/name; d.mkdir(mode=0o700); (d/'state').write_text('UWVM-WSEA-STATE-1\n0 0 -\n'); (d/'state').chmod(0o600)
        roots=b''.join(dict.fromkeys(Path(c['pki']['root']).read_bytes() for c in selected)); (d/'roots.pem').write_bytes(roots)
        algorithms=list(dict.fromkeys(c['algorithm'] for c in selected)); pins=[c['pki']['pin'] for c in selected]
        text=f'UWVM-WSEA-POLICY-1\npolicy_version=1\ntrust_root={d}/roots.pem\nstate_dir={d}\nmax_crl_age_seconds=86400\nmax_module_bytes=1048576\nmodule=matrix.app|uwvm2|{pins[0]}|1|0|0|'+','.join(algorithms)+'\n'
        text+=''.join('module_signer=matrix.app|'+pin+'\n' for pin in pins[1:]); text+=f'module_threshold=matrix.app|{threshold}\n'
        (d/'policy').write_text(text);return d
    def request(d,module):
        return {'schema':'wsea-sdk-1','operation':'verify','module':b64(module),'trust':{
            'policy':b64((d/'policy').read_bytes()),'roots':b64((d/'roots.pem').read_bytes()),
            'state':b64((d/'state').read_bytes()),'revoked_spkis':sorted(v.name[8:] for v in d.glob('revoked-*'))}}
    def signed(d,engine,c,module,m,append=False,partial=False):
        req=request(d,module);req['operation']='sign';req['signing']={
            'key':b64(Path(c['pki']['key']).read_bytes()),'certificates':b64(Path(c['pki']['certificate']).read_bytes()),
            'crls':b64(Path(c['pki']['crl']).read_bytes()),'manifest':dict(m,algorithm=c['algorithm']),
            'append':append,'allow_partial':partial}
        result=engine.request(req)
        if result['status'] not in ('VERIFIED_SNAPSHOT','SIGNED_PARTIAL'):raise RuntimeError(f'{engine.name} signing {c["algorithm"]}: {result}')
        return base64.b64decode(result['module']),result
    def verify_all(d,module,name,allow=True,commit=True):
        req=request(d,module)
        for engine in engines:
            answer=engine.request(req)
            if (answer['status']=='VERIFIED_SNAPSHOT')!=allow: raise RuntimeError(f'{name} {engine.name}: {answer}')
        path=d/(name+'.wasm');path.write_bytes(module)
        cli=subprocess.run([str(a.native_cosign.resolve()),'wasm','secure','verify',str(path),'--policy',str(d/'policy')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90)
        if (cli.returncode==0)!=allow:raise RuntimeError(f'{name} native cosign: '+cli.stderr.decode(errors='replace'))
        if commit:
            answer=native.line(f'{d}/policy\t{path}\t'.encode()).decode()
            if (answer=='0\tALLOW')!=allow:raise RuntimeError(f'{name} native: {answer}')
        record(name)
    now=int(time.time())
    m={'embedded':True,'module_id':'matrix.app','version':1,'security_epoch':0,'not_before':now-60,'not_after':now+7200,'abi':'uwvm2','capabilities':0}
    unsigned=bytes.fromhex('0061736d0100000001040160000003020100070a01065f737461727400000a040102000b')
    try:
        for algorithm in manifest['algorithms']:
            case=next(c for c in cases if c['name']==algorithm+' valid exact profile')
            d=context('single-'+algorithm,[case])
            for engine in engines:
                module,result=signed(d,engine,case,unsigned,m)
                if result['status']!='VERIFIED_SNAPSHOT' or result['manifest']['algorithm']!=algorithm:raise RuntimeError('wrong signing profile')
                verify_all(d,module,engine.name+'-'+algorithm)
            source=d/'unsigned.wasm';source.write_bytes(unsigned);signed_path=d/'native-produced.wasm'
            fmt=lambda n:datetime.fromtimestamp(n,timezone.utc).isoformat().replace('+00:00','Z')
            native_sign=subprocess.run([str(a.native_cosign.resolve()),'wasm','secure','sign',str(source),'--policy',str(d/'policy'),
                '--key',case['pki']['key'],'--certificate',case['pki']['certificate'],'--crl',case['pki']['crl'],
                '--module-id','matrix.app','--module-version','1','--algorithm',algorithm,
                '--not-before',fmt(m['not_before']),'--not-after',fmt(m['not_after']),'--output',str(signed_path)],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)
            if native_sign.returncode:raise RuntimeError('native signing failed: '+native_sign.stderr.decode(errors='replace'))
            verify_all(d,signed_path.read_bytes(),'native-produced-'+algorithm)
        selected=[];seen=set()
        for c in cases:
            k=c['pki']
            if c['expected']=='ALLOW' and k['pin'] not in seen and k['family'] in ('EC','ED25519','RSA'):
                selected.append(c);seen.add(k['pin'])
                if len(selected)==8:break
        if len(selected)!=8:raise RuntimeError('eight distinct qualified signer keys required')
        # Build a single mixed-family bundle with contributions from all three
        # real runtimes. Every intermediate remains below execution quorum.
        d=context('eight-signers',selected,8);module=unsigned;partials=[]
        for i,c in enumerate(selected):
            engine=engines[i%len(engines)]
            module,result=signed(d,engine,c,module,m,append=i>0,partial=i<7)
            if result['status']!=('SIGNED_PARTIAL' if i<7 else 'VERIFIED_SNAPSHOT'):raise RuntimeError('partial signature status lost')
            if i<7:
                partials.append(module);verify_all(d,module,f'partial-{i+1}-of-8',False,False)
        verify_all(d,module,'complete-8-of-8')
        tampered=bytearray(module);tampered[4]^=1;verify_all(d,bytes(tampered),'tampered-module',False)
        revoked=selected[-1]['pki']['pin'];(d/('revoked-'+revoked)).write_bytes(b'')
        verify_all(d,module,'permanent-revocation-in-quorum',False)
        # A duplicate authorized key never contributes a second vote, including
        # through a different algorithm label for the same EC key.
        duplicate=context('duplicate-vote',[selected[0],selected[3]],2)
        first,_=signed(duplicate,engines[0],selected[0],unsigned,m,partial=True)
        dup=request(duplicate,first);dup['operation']='sign';dup['signing']={'key':b64(Path(selected[0]['pki']['key']).read_bytes()),'certificates':b64(Path(selected[0]['pki']['certificate']).read_bytes()),'crls':b64(Path(selected[0]['pki']['crl']).read_bytes()),'manifest':dict(m,algorithm=selected[0]['algorithm']),'append':True,'allow_partial':True}
        for engine in engines:
            answer=engine.request(dup)
            if answer['status']=='REJECTED':continue
            if answer['status']!='SIGNED_PARTIAL' or len(answer['manifest']['signer_spkis'])!=1:raise RuntimeError('duplicate signer counted twice')
            verify_all(duplicate,base64.b64decode(answer['module']),'duplicate-'+engine.name,False)
        record('duplicate-key-is-not-a-second-vote')
        d2=context('rotation',[selected[0],selected[3]],1)
        first,_=signed(d2,engines[0],selected[0],unsigned,m)
        second,_=signed(d2,engines[1],selected[3],unsigned,dict(m,version=2))
        verify_all(d2,second,'authorized-new-key-version-2')
        verify_all(d2,first,'same-publisher-version-1-rollback',False)
        wide,_=signed(d2,engines[2],selected[3],unsigned,dict(m,version=18446744073709551615,security_epoch=9007199254740993))
        verify_all(d2,wide,'full-width-uint64-counters')
        # Full UWVM execution authorization consumes the same eight-signature
        # container. Use a fresh state and a valid 2-of-2 module with no imports.
        mix=[selected[0],selected[3],selected[4]];d3=context('full-vm',mix,3);full=unsigned
        for i,c in enumerate(mix):full,_=signed(d3,engines[i],c,full,m,append=i>0,partial=i<2)
        verify_all(d3,full,'mixed-rsa-ecdsa-eddsa')
        malformed=bytearray(full);malformed[-30]^=1
        verify_all(d3,bytes(malformed),'bad-present-contribution',False)
        file=d3/'mixed-rsa-ecdsa-eddsa.wasm'
        vm=subprocess.run([str(a.uwvm.resolve()),'--runtime-int','--secure','module',str(file),str(d3/'policy'),'--run',str(file)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)
        (out/'full-vm.stdout.log').write_bytes(vm.stdout);(out/'full-vm.stderr.log').write_bytes(vm.stderr)
        if vm.returncode:raise RuntimeError('actual UWVM execution authorization failed: '+vm.stderr.decode(errors='replace'))
        record('uwvm-secure-execution-mixed-three-signatures')
        badfile=d3/'bad-present-contribution.wasm'
        badvm=subprocess.run([str(a.uwvm.resolve()),'--runtime-int','--secure','module',str(badfile),str(d3/'policy'),'--run',str(badfile)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)
        if badvm.returncode not in (126,127) or not any(prefix in badvm.stderr for prefix in (b'SIG_',b'CERT_')):
            raise RuntimeError('actual UWVM execution did not reject the bad present signature')
        record('uwvm-secure-refuses-invalid-contribution')
        # File adapters must authenticate local trust independently of stdin JSON.
        for runtime in ('wasmtime','node','uwvm'):
            argv=['python3',str(ROOT/'wasm/run.py'),'--runtime',runtime,'--assets',str(assets)]
            if runtime=='uwvm':argv+=['--engine',str(a.uwvm.resolve())]
            argv+=['verify',str(file),'--policy',str(d3/'policy')]
            proc=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180)
            if proc.returncode or json.loads(proc.stdout)['status']!='VERIFIED':raise RuntimeError('protected host adapter '+runtime+': '+proc.stderr.decode(errors='replace'))
            record('protected-file-adapter-'+runtime)
    finally:
        for engine in [*engines,native]:engine.close()
    print(json.dumps({'status':'PASS','checks':len(records),'engines':[e.name for e in engines]}),flush=True)


if __name__=='__main__':main()
