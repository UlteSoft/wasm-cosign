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
        self.assertEqual(gui.exact_json({'v': 2**64-1, 'embedded': True}), {'v': '18446744073709551615', 'embedded': True})

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


@unittest.skipUnless(os.name=='posix', 'Executable fixture uses a POSIX shebang')
class HTTPBoundary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory=tempfile.TemporaryDirectory(prefix='unit-',dir=SCRATCH)
        cls.root=Path(cls.directory.name)
        cls.binary=cls.root/'mock-cosign'
        cls.binary.write_text('#!'+sys.executable+'\nprint("wasm-cosign test WSEA v2")\n')
        cls.binary.chmod(0o700)
        cls.app=gui.Application(cls.binary,[cls.root],1)
        cls.server=gui.LocalServer(('127.0.0.1',0),cls.app)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join();cls.directory.cleanup()

    def request(self,path='/api/config',method='GET',data=None,headers=None,auth=True):
        h={'Host':self.server.authority}
        if auth:h['Authorization']='Bearer '+self.app.token
        if method=='POST':h.update({'Origin':self.server.origin,'Content-Type':'application/json'})
        if headers:h.update(headers)
        body=json.dumps(data) if data is not None and not isinstance(data,str) else data
        conn=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=3)
        conn.request(method,path,body=body,headers=h);response=conn.getresponse()
        status=response.status;raw=response.read();response_headers=dict(response.getheaders());conn.close()
        return status,raw,response_headers

    def test_authentication_and_no_token_exposure(self):
        self.assertEqual(self.request(auth=False)[0],401)
        self.assertEqual(self.request(headers={'Authorization':'Bearer wrong'})[0],401)
        status,body,_=self.request()
        self.assertEqual(status,200)
        self.assertNotIn(self.app.token.encode(),body)
        self.assertEqual(self.request('/api/jobs',method='POST',data={'command':'version','fields':{}},auth=False)[0],401)

    def test_host_dns_rebinding_and_origin(self):
        for host in ['evil.test','localhost:'+str(self.server.server_port),'127.0.0.1:1','127.0.0.1:'+str(self.server.server_port)+'.evil']:
            self.assertEqual(self.request(headers={'Host':host})[0],403)
        for h in [{'Origin':'https://evil.test'},{'Origin':'null'},{'Sec-Fetch-Site':'cross-site'}]:
            self.assertEqual(self.request(headers=h)[0],403)
        self.assertEqual(self.request('/api/jobs',method='POST',data={'command':'version','fields':{}},headers={'Origin':''})[0],403)
        self.assertEqual(self.request('/api/jobs',method='OPTIONS',auth=False)[0],501)

    def test_static_allowlist_csp_no_cors(self):
        status,body,h=self.request('/',auth=False)
        self.assertEqual(status,200)
        self.assertIn('frame-ancestors \'none\'',h['Content-Security-Policy'])
        self.assertEqual(h['Cache-Control'],'no-store')
        self.assertEqual(h['X-Content-Type-Options'],'nosniff')
        self.assertNotIn('Access-Control-Allow-Origin',h)
        self.assertNotIn(self.app.token.encode(),body)
        for path in ['/../server.py','/%2e%2e/server.py','/server.py','/api/file?path=/etc/passwd','/app.js?token=x']:
            self.assertEqual(self.request(path)[0],404)

    def test_json_validation(self):
        for body in ['[]','{}','{','{"command":"version","command":"help","fields":{}}','{"command":"version","fields":{"extra":"x"}}']:
            self.assertEqual(self.request('/api/jobs','POST',body)[0],400)
        self.assertEqual(self.request('/api/jobs','POST','{}',{'Content-Type':'text/plain'})[0],415)
        self.assertEqual(self.request('/api/jobs','POST','x'*(gui.MAX_BODY+1))[0],413)
        self.assertEqual(self.request('/api/jobs','POST','{}',{'Transfer-Encoding':'chunked'})[0],400)

    def test_browse_roots_and_no_contents(self):
        (self.root/'secret.pem').write_text('CONTENTS_MUST_NOT_BE_RETURNED')
        (self.root/'outside').symlink_to(self.root.parent,target_is_directory=True)
        status,body,_=self.request('/api/browse','POST',{'path':str(self.root)})
        self.assertEqual(status,200)
        self.assertIn(b'secret.pem',body)
        self.assertNotIn(b'CONTENTS_MUST_NOT_BE_RETURNED',body)
        self.assertNotIn(b'outside',body)
        for path in [str(self.root.parent),str(self.root/'outside'),'/etc']:
            self.assertEqual(self.request('/api/browse','POST',{'path':path})[0],400)

    def test_preview_and_native_output_fail_closed(self):
        status,body,_=self.request('/api/preview','POST',{'command':'sign','fields':sign_fields()})
        self.assertEqual(status,200)
        self.assertIsNone(self.app.active)
        job=self.app.submit('sign',sign_fields())
        deadline=time.monotonic()+3
        while self.app.active and time.monotonic()<deadline:time.sleep(.02)
        finished=self.app.get_job(job['id'])
        # Mock identifies itself but doesn't emit native verification JSON.
        self.assertEqual(finished['state'],'failed')
        self.assertIn('protocol_error',finished)

    def test_serialization_partial_and_shutdown(self):
        release=threading.Event()
        def held(*_):
            release.wait(2)
            return {'exit_code':0,'stdout':json.dumps({'status':'SIGNED_PARTIAL','manifest':{'version':2**64-1}}),'stderr':'','seconds':0,'interrupted':None}
        with patch.object(gui,'run_bounded',held):
            job=self.app.submit('sign',sign_fields() | {'allow-partial':True})
            with self.assertRaises(gui.InputError):self.app.submit('version',{})
            release.set();self.app.worker.join(timeout=3)
            finished=self.app.get_job(job['id'])
            self.assertEqual(finished['state'],'partial')
            self.assertEqual(finished['document']['manifest']['version'],str(2**64-1))
        local=gui.Application(self.binary,[self.root],3)
        with patch.object(gui,'run_bounded',lambda args,timeout,stop:gui_runner([sys.executable,'-c','import time;time.sleep(60)'],timeout,stop)):
            local.submit('version',{})
            local.close()
            self.assertIsNone(local.active)
            self.assertEqual(list(local.jobs.values())[-1]['state'],'interrupted')


gui_runner=gui.run_bounded
if __name__=='__main__':
    unittest.main(verbosity=2)
