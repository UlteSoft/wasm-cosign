#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors. Apache-2.0.
"""Bridge boundary tests. All scratch data stays in the repository's .tmp."""
from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server as gui
import native_picker

SCRATCH = Path(__file__).resolve().parents[2] / '.tmp' / 'webgui'
SCRATCH.mkdir(parents=True, exist_ok=True)


def sign_fields():
    return {'module': '/local/input.wasm', 'policy': '/local/policy', 'key': '/local/key.pem',
            'certificate': '/local/cert.pem', 'crl': '/local/crl.pem', 'module-id': 'example.app',
            'module-version': '1', 'not-before': '2026-01-01T00:00:00Z',
            'not-after': '2026-01-02T00:00:00Z', 'output': '/local/signed.wasm'}


class Arguments(unittest.TestCase):
    def test_exact_unsigned_64_bit(self):
        fields = sign_fields() | {'module-version': '18446744073709551615'}
        self.assertIn('--module-version=18446744073709551615', gui.build_argv('/bin/cosign', 'sign', fields))
        for invalid in ['18446744073709551616', '-1', '1.1', '1e3', '01', 123, True]:
            with self.subTest(invalid=invalid), self.assertRaises(gui.InputError):
                gui.build_argv('/bin/cosign', 'sign', fields | {'module-version': invalid})

    def test_no_shell_or_flag_injection(self):
        fields = sign_fields() | {'key': '/local/$(touch SENTINEL); key.pem', 'module-id': '--help'}
        args = gui.build_argv('/binary with spaces/cosign', 'sign', fields)
        self.assertIn('--key=/local/$(touch SENTINEL); key.pem', args)
        self.assertIn('--module-id=--help', args)
        self.assertEqual(args[-2:], ['--', '/local/input.wasm'])
        for field in [{'extra-args': '--insecure'}, {'key': 'relative.key'}, {'key': '/local/../key'}, {'key': '/local/\x00key'}]:
            with self.assertRaises(gui.InputError):
                gui.build_argv('/bin/cosign', 'sign', sign_fields() | field)
        for command in ['sh', 'sign-blob', 'download', 'wasm secure sign', ['sign']]:
            with self.assertRaises(gui.InputError):
                gui.build_argv('/bin/cosign', command, {})

    def test_policy_update_preserves_omitted_fields(self):
        args = gui.build_argv('/bin/cosign', 'policy-update', {'policy':'/local/policy','policy-version':'2','algorithms':'','minimum-version':''})
        self.assertEqual(args, ['/bin/cosign','wasm','secure','policy-update','--policy=/local/policy','--policy-version=2'])
        with self.assertRaises(gui.InputError):
            gui.build_argv('/bin/cosign','policy-update',{'policy':'/local/policy','policy-version':'2','minimum-version':'0'})
        with self.assertRaises(gui.InputError):
            gui.build_argv('/bin/cosign','policy-update',{'policy':'/local/policy','policy-version':'2','module-id':'app','additional-certificate':['/local/cert'],'clear-additional-signers':True})

    def test_multisign_modes_and_output(self):
        fields = sign_fields()
        for invalid in [{'append-signature':True,'replace-signature':True}, {'output':''}, {'output':fields['module']}, {'in-place':'true'}, {'allow-partial':'false'}]:
            with self.assertRaises(gui.InputError):
                gui.build_argv('/bin/cosign','sign',fields | invalid)
        args = gui.build_argv('/bin/cosign','sign',fields | {'output':'','in-place':True,'append-signature':True,'allow-partial':True})
        self.assertIn('--append-signature', args)
        self.assertIn('--allow-partial', args)
        self.assertFalse(any(x.startswith('--output') or x.startswith('--in-place') for x in args))

    def test_exact_algorithm_allowlist_and_time(self):
        for algorithm in gui.ALGORITHMS:
            self.assertIn('--algorithm='+algorithm,gui.build_argv('/bin/cosign','sign',sign_fields() | {'algorithm':algorithm}))
        for invalid in ['EdDSA','Ed448','ES256,ES256','rsa','ES256,unknown']:
            with self.assertRaises(gui.InputError):
                gui.build_argv('/bin/cosign','sign',sign_fields() | {'algorithm':invalid})
        for invalid in ['2026-02-30T00:00:00Z','yesterday','1969-01-01T00:00:00Z','2026-01-01']:
            with self.assertRaises(gui.InputError):
                gui.build_argv('/bin/cosign','sign',sign_fields() | {'not-before':invalid})
        with self.assertRaises(gui.InputError):
            gui.build_argv('/bin/cosign','sign',sign_fields() | {'not-after':'2025-01-01T00:00:00Z'})

    def test_https_only(self):
        fields = {'output':'/local/module.wasm','policy':'/local/policy'}
        for invalid in ['http://host/x','file:///secret','https://user:pass@host/x','https://host/x#frag','https://host:bad/x']:
            with self.assertRaises(gui.InputError):
                gui.build_argv('/bin/cosign','fetch',fields | {'url':invalid})
        self.assertEqual(gui.build_argv('/bin/cosign','fetch',fields | {'url':'https://localhost:1234/x'})[-2:],['--','/local/module.wasm'])

    def test_bounded_runner(self):
        result=gui.run_bounded([sys.executable,'-c','import time;time.sleep(5)'],.1)
        self.assertEqual(result['interrupted'],'timeout')
        result=gui.run_bounded([sys.executable,'-c','import sys;sys.stdout.write("x"*100000)'],2,output_limit=100)
        self.assertEqual(result['interrupted'],'output-limit')
        self.assertLessEqual(len(result['stdout']),100)
        # Strings that look like shell substitutions remain ordinary argv data.
        result=gui.run_bounded([sys.executable,'-c','import sys;print(sys.argv[1])','$(echo unexpected); --help'],2)
        self.assertEqual(result['stdout'].strip(),'$(echo unexpected); --help')


def manifest():
    return {'embedded':True,'module_id':'example.app','version':2**64-1,'security_epoch':0,
            'capabilities':0,'not_before':1794000000,'not_after':1794003600,
            'signature_algorithms':['ES256'],'signer_spkis':['a'*64]}


def native(status='VERIFIED', code=0, **extra):
    return {'exit_code':code,'stdout':json.dumps({'status':status,'manifest':manifest()}),
            'stderr':'','seconds':0,'interrupted':None,**extra}


class DesktopPicker(unittest.TestCase):
    def test_helper_protocol_does_not_return_diagnostics(self):
        with patch.object(gui, 'run_bounded', return_value=native(stdout='{"path":"/chosen/key.pem"}')) as runner:
            self.assertEqual(gui.choose_local_file('key','zh',threading.Event()),'/chosen/key.pem')
            self.assertEqual(runner.call_args.args[0][-2:],['key','zh'])
        with patch.object(gui, 'run_bounded', return_value=native(code=2,stdout='')):
            self.assertIsNone(gui.choose_local_file('key','en',threading.Event()))
        with patch.object(gui, 'run_bounded', return_value=native(code=1,stderr='/private/failure')):
            with self.assertRaisesRegex(gui.InputError, '^PICKER_UNAVAILABLE$'):
                gui.choose_local_file('key','en',threading.Event())

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Zenity backend is Linux-specific')
    def test_desktop_adapter_uses_argument_arrays_and_cancellation(self):
        from types import SimpleNamespace
        with patch.object(native_picker.shutil,'which',return_value='/usr/bin/zenity'), patch.object(native_picker.subprocess,'run') as run:
            run.return_value=SimpleNamespace(returncode=0,stdout='/local/$(literal).wasm\n')
            self.assertEqual(native_picker.select('module-output','en'),'/local/$(literal).wasm')
            self.assertIn('--save',run.call_args.args[0])
            self.assertNotIn('shell',run.call_args.kwargs)
            run.return_value=SimpleNamespace(returncode=1,stdout='')
            self.assertIsNone(native_picker.select('key','zh'))


@unittest.skipUnless(os.name=='posix', 'Executable fixture uses a POSIX shebang')
class HTTPBoundary(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory(prefix='private-unit-',dir=SCRATCH)
        self.root=Path(self.directory.name)
        self.binary=self.root/'mock-cosign'
        self.binary.write_text('#!'+sys.executable+'\nprint("wasm-cosign test WSEA v2")\n')
        self.binary.chmod(0o700)
        self.selected=self.root/'user-chosen.pem'
        self.selected.write_text('SECRET_KEY_CONTENT_DO_NOT_SEND')
        self.app=gui.Application(self.binary,1,picker=lambda *_:str(self.selected))
        self.server=gui.LocalServer(('127.0.0.1',0),self.app)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join();self.directory.cleanup()

    def request(self,path='/api/config',method='GET',data=None,headers=None,auth=True):
        h={'Host':self.server.authority}
        if auth:h['Authorization']='Bearer '+self.app.token
        if method=='POST':h.update({'Origin':self.server.origin,'Content-Type':'application/json'})
        if headers:h.update(headers)
        body=json.dumps(data) if data is not None and not isinstance(data,str) else data
        conn=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=3)
        conn.request(method,path,body=body,headers=h);response=conn.getresponse()
        status=response.status;raw=response.read();response_headers=dict(response.getheaders());conn.close()
        self.assertNotIn(str(self.root).encode(),raw)
        self.assertNotIn(b'SECRET_KEY_CONTENT_DO_NOT_SEND',raw)
        self.assertNotIn(self.app.token.encode(),raw)
        return status,raw,response_headers

    def fields(self):
        f=sign_fields()
        for name,spec in gui.SCHEMAS['sign'].items():
            if name in f and spec.rstrip('!')=='path':
                path=self.root/'new.wasm' if name=='output' else self.selected
                f[name]=self.app.register_file(str(path),gui.file_role('sign',name))['id']
        return f

    def finished(self,command,fields,result):
        with patch.object(gui,'run_bounded',return_value=result):
            status,raw,_=self.request('/api/jobs','POST',{'command':command,'fields':fields})
            self.assertEqual(status,202,raw)
            job=json.loads(raw);self.app.worker.join(3)
        status,raw,_=self.request('/api/jobs/'+job['id'])
        self.assertEqual(status,200)
        return json.loads(raw)

    def test_authentication_and_no_local_information(self):
        self.assertEqual(self.request(auth=False)[0],401)
        self.assertEqual(self.request(headers={'Authorization':'Bearer wrong'})[0],401)
        status,body,_=self.request()
        self.assertEqual(status,200)
        self.assertEqual(set(json.loads(body)),{'algorithms','jobs','active_job','selection'})
        self.assertEqual(self.request('/api/selections','POST',{'command':'sign','field':'key','language':'zh'},auth=False)[0],401)

    def test_host_and_origin(self):
        for host in ['evil.test','localhost:'+str(self.server.server_port),'127.0.0.1:1']:
            self.assertEqual(self.request(headers={'Host':host})[0],403)
        for h in [{'Origin':'https://evil.test'},{'Origin':'null'},{'Sec-Fetch-Site':'cross-site'}]:
            self.assertEqual(self.request(headers=h)[0],403)
        self.assertEqual(self.request('/api/jobs','POST',{},headers={'Origin':''})[0],403)
        status,body,h=self.request('/api/jobs',method='OPTIONS',auth=False)
        self.assertEqual(status,501);self.assertIn('application/json',h['Content-Type'])

    def test_removed_surfaces_and_static_headers(self):
        status,body,h=self.request('/',auth=False)
        self.assertEqual(status,200)
        self.assertIn("frame-ancestors 'none'",h['Content-Security-Policy'])
        self.assertEqual(h['Cache-Control'],'no-store')
        self.assertNotIn('Access-Control-Allow-Origin',h)
        for path in ['/../server.py','/%2e%2e/server.py','/server.py','/api/file?path=/etc/passwd','/app.js?token=x']:
            self.assertEqual(self.request(path)[0],404)
        for path in ['/api/browse','/api/preview','/api/upload']:
            self.assertEqual(self.request(path,'POST',{'path':str(self.root)})[0],404)
        for command in ['help','version','sign-blob','sh']:
            self.assertEqual(self.request('/api/jobs','POST',{'command':command,'fields':{}})[0],400)

    def test_json_validation_no_exception_echo(self):
        for body in ['[]','{}','{','{"command":"verify","command":"help","fields":{}}',
                     '{"command":"sign","fields":{"module":NaN}}',
                     {'command':'sign','fields':{'extra-'+str(self.root):'x'}},
                     {'command':['sign'],'fields':{}}, {'command':'sign','fields':sign_fields()}]:
            status,raw,_=self.request('/api/jobs','POST',body)
            self.assertEqual(status,400,raw)
            self.assertRegex(json.loads(raw)['error'],r'^[A-Z_]+$')
        self.assertEqual(self.request('/api/jobs','POST','{}',{'Content-Type':'text/plain'})[0],415)
        self.assertEqual(self.request('/api/jobs','POST','x'*(gui.MAX_BODY+1))[0],413)
        self.assertEqual(self.request('/api/jobs','POST','{}',{'Transfer-Encoding':'chunked'})[0],400)

    def test_desktop_selection_returns_only_explicit_name_and_handle(self):
        status,raw,_=self.request('/api/selections','POST',{'command':'sign','field':'key','language':'zh'})
        self.assertEqual(status,202);ident=json.loads(raw)['id'];self.app.picker_worker.join(3)
        status,raw,_=self.request('/api/selections/'+ident)
        result=json.loads(raw);self.assertEqual(result['state'],'selected')
        self.assertEqual(set(result['file']),{'id','name'})
        self.assertEqual(result['file']['name'],self.selected.name)
        self.assertEqual(set(self.app.config()),{'algorithms','jobs','active_job','selection'})
        status,_,_=self.request('/api/selections','POST',{'command':'sign','field':'key','language':'en','path':str(self.selected)})
        self.assertEqual(status,400)

    def test_file_capabilities_reject_wrong_role_and_foreign_handle(self):
        f=self.fields()
        for invalid in [str(self.selected),'0'*32,[],True,f['certificate']]:
            self.assertEqual(self.request('/api/jobs','POST',{'command':'sign','fields':f|{'key':invalid}})[0],400)
        # Browser cannot turn a selected input into a writable output capability.
        self.assertEqual(self.request('/api/jobs','POST',{'command':'sign','fields':f|{'output':f['module']}})[0],400)

    def test_cancel_and_picker_failure_do_not_leak(self):
        for pick,expected in [(lambda *_:None,'cancelled'),(lambda *_:(_ for _ in ()).throw(OSError(str(self.root))),'failed')]:
            self.app.picker=pick
            job=self.app.select_file('sign','key','en');self.app.picker_worker.join(3)
            status,raw,_=self.request('/api/selections/'+job['id'])
            self.assertEqual(json.loads(raw)['state'],expected)

    def test_raw_native_failures_and_policy_text_are_discarded(self):
        for text,expected in [('CERT_006: private path '+str(self.root),'CERT_006'),(str(self.root),'OPERATION_FAILED')]:
            job=self.finished('sign',self.fields(),native(code=1,stderr=text,stdout='SECRET_KEY_CONTENT_DO_NOT_SEND'))
            self.assertEqual(job['error'],expected)
            self.assertEqual(set(job),{'id','command','state','error'})
        f={'policy':self.app.register_file(str(self.selected),'policy')['id'],'policy-version':'2'}
        job=self.finished('policy-update',f,native(stdout='Updated protected policy '+str(self.root),stderr=str(self.root)))
        self.assertEqual(job['document'],{'status':'COMPLETED'})
        self.request()  # Config history must remain sanitized too.

    def test_json_allowlist_and_exact_uint64(self):
        m=manifest()|{'debug':str(self.root),'binary':str(self.binary)}
        job=self.finished('sign',self.fields(),native(stdout=json.dumps({'status':'VERIFIED','manifest':m,'stderr':str(self.root)})))
        self.assertEqual(job['state'],'succeeded')
        result=job['document']['manifest']
        self.assertEqual(result['version'],str(2**64-1));self.assertEqual(result['signer_count'],1)
        self.assertNotIn('debug',result);self.assertNotIn('signer_spkis',result)
        self.assertNotIn('fields',job);self.assertNotIn('argv',job)

    def test_unexpected_json_fails_closed(self):
        for raw in ['text', '{}', '{"status":"VERIFIED","status":"SIGNED_PARTIAL"}',
                    json.dumps({'status':'VERIFIED','manifest':manifest()|{'version':True}}),
                    json.dumps({'status':'VERIFIED','manifest':manifest()|{'module_id':str(self.root)}}),
                    json.dumps({'status':'VERIFIED','manifest':manifest()|{'signature_algorithms':['unknown']}}),
                    json.dumps({'status':'SIGNED_PARTIAL','manifest':manifest()})]:
            with self.subTest(raw=raw):
                job=self.finished('sign',self.fields(),native(stdout=raw))
                self.assertEqual(job['state'],'failed');self.assertEqual(job['error'],'INVALID_RESULT')

    def test_multisign_followup_has_no_paths_or_signing_secrets(self):
        (self.root/'new.wasm').write_bytes(b'\0asm\x01\0\0\0')
        job=self.finished('sign',self.fields()|{'allow-partial':True},native('SIGNED_PARTIAL'))
        self.assertEqual(job['state'],'partial')
        status,raw,_=self.request('/api/jobs/'+job['id']+'/next','POST',{'action':'append'})
        self.assertEqual(status,200);next_=json.loads(raw)
        self.assertEqual(next_['fields']['module-version'],str(2**64-1))
        self.assertTrue(next_['fields']['append-signature'])
        for field in ['key','certificate','crl','output']:
            self.assertNotIn(field,next_['fields'])
        status,raw,_=self.request('/api/jobs/'+job['id']+'/next','POST',{'action':'verify'})
        self.assertEqual(set(json.loads(raw)['fields']),{'module','policy'})

    def test_serialization_limits_and_shutdown(self):
        release=threading.Event()
        def held(*_):
            release.wait(2);return native()
        with patch.object(gui,'run_bounded',held):
            self.app.submit('sign',self.fields())
            self.assertEqual(self.request('/api/jobs','POST',{'command':'sign','fields':self.fields()})[0],400)
            self.assertEqual(self.request('/api/selections','POST',{'command':'sign','field':'key','language':'en'})[0],400)
            release.set();self.app.worker.join(3)
        for _ in range(22):
            self.finished('sign',self.fields(),native())
        self.assertEqual(len(self.app.jobs),20);self.assertEqual(len(self.app.inputs),20)
        runner=gui.run_bounded
        with patch.object(gui,'run_bounded',lambda args,timeout,stop:runner([sys.executable,'-c','import time;time.sleep(60)'],timeout,stop)):
            job=self.app.submit('sign',self.fields());self.app.close()
        self.assertEqual(self.app.get_job(job['id'])['state'],'interrupted')
        self.assertFalse(self.app.files);self.assertFalse(self.app.inputs)


if __name__=='__main__':
    unittest.main(verbosity=2)
