/* Copyright 2026 The Sigstore Authors. Apache-2.0.
 * No browser automation: execute the real UI state/HTTP code in a minimal DOM
 * fixture. Run against a disposable local test server, never a user session.
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const settings=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
const origin=new URL(settings.url).origin;
const token=new URL(settings.url).hash.slice(7);
const replies=[];
const elements=new Map();
const form={elements:[],querySelector:()=>null,querySelectorAll:()=>[]};
function element(selector){if(!elements.has(selector))elements.set(selector,{innerHTML:'',textContent:'',value:'',disabled:false,classList:{add(){},remove(){},toggle(){}},scrollIntoView(){},focus(){}});return elements.get(selector);}
const listeners={};
const context=vm.createContext({
  document:{documentElement:{lang:''},title:'',querySelector:s=>s==='#operation-form'?form:element(s),querySelectorAll:()=>[],addEventListener:(event,fn)=>{(listeners[event]??=[]).push(fn);}},
  window:{scrollTo(){}},location:{hash:'',pathname:'/'},history:{replaceState(){}},URLSearchParams,
  navigator:{clipboard:{writeText:async text=>{assert(!text.includes('/home/'));JSON.parse(text);}}},
  setTimeout,clearTimeout,Date,console,
  fetch:async (url,options)=>{
    options.headers.Origin=origin;
    const response=await fetch(origin+url,options);
    const text=await response.text();replies.push(text);
    assert(!/"(?:argv|display|stdout|stderr|binary|browse_roots|path)"\s*:/.test(text),'private field in HTTP');
    assert(!/\/home\/|\/\.tmp\/|BEGIN .*PRIVATE KEY/.test(text),'local information in HTTP');
    return {ok:response.ok,json:async()=>JSON.parse(text)};
  }
});
vm.runInContext(fs.readFileSync(path.join(__dirname,'../static/app.js'),'utf8'),context);
const run = code=>vm.runInContext(code,context);
const waitUntil=async test=>{const deadline=Date.now()+10000;while(!test()){if(Date.now()>deadline)throw Error('state deadline');await new Promise(r=>setTimeout(r,30));}};
(async()=>{
  await run(`connect(${JSON.stringify(token)})`);
  assert.equal(run('state.page'),'sign');
  let html=element('#app').innerHTML;
  for(const field of ['module','policy','key','certificate','crl','output'])assert(html.includes(`data-file-field="${field}"`));
  assert(!/浏览目录|原始输出|命令预览|UWVM|127\.0\.0\.1/.test(html));
  for(const field of ['module','policy','key','certificate','crl','output']){
    await run(`selectFile('${field}',false)`);await waitUntil(()=>!run('state.picking'));
    assert(run(`state.forms.sign['${field}']`),'missing selected handle');
  }
  await run('launch()');assert.equal(run('state.step'),2);
  assert.equal(run('state.jobs.length'),0,'Next must not run a native command');
  run(`state.forms.sign['module-id']='gui.test';state.forms.sign['not-before']=${JSON.stringify(settings.times['not-before'])};state.forms.sign['not-after']=${JSON.stringify(settings.times['not-after'])};state.forms.sign['allow-partial']=true;state.lang='en';render()`);
  assert(element('#app').innerHTML.includes('Signature settings'));
  assert.equal(run("state.forms.sign['module-id']"),'gui.test');
  for(const [algorithm,expected] of [['ES256','partial'],['RS256','partial'],['Ed25519','succeeded']]){
    if(algorithm!=='ES256'){
      const previous=run('state.jobs[0].id');
      await run(`nextOperation('${previous}','append')`);
      assert.equal(run('state.step'),1);
      assert.equal(run("state.forms.sign['module-id']"),'gui.test');
      assert(!run('state.forms.sign.key'));
      assert(!run('state.forms.sign.output'));
      for(const field of ['key','certificate','crl','output']){
        await run(`selectFile('${field}',false)`);await waitUntil(()=>!run('state.picking'));
      }
      await run('launch()');assert.equal(run('state.step'),2);
      run(`state.forms.sign.algorithm='${algorithm}';state.forms.sign['allow-partial']=${algorithm!=='Ed25519'}`);
    }
    await run('launch()');await waitUntil(()=>!run('state.active'));
    assert.equal(run('state.jobs[0].state'),expected,JSON.stringify(run('state.jobs[0]')));
  }
  assert.equal(run('state.jobs[0].document.manifest.signer_count'),3);
  const signed=run('state.jobs[0].id');
  await run(`nextOperation('${signed}','verify')`);await run('launch()');await waitUntil(()=>!run('state.active'));
  assert.equal(run('state.jobs[0].state'),'succeeded');
  assert(element('#result-area').innerHTML.includes('Verification passed'));
  run("state.lang='zh';navigate('more')");
  html=element('#app').innerHTML;
  for(const t of ['创建策略','更新策略','获取并校验'])assert(html.includes(t));
  for(const page of ['policy-init','policy-update','fetch']){
    run(`navigate('${page}')`);assert(element('#app').innerHTML.includes('返回工具'));
  }
  run("navigate('policy-update')");
  assert(!run("state.forms['policy-update']['signature-threshold']"),'Update must not reset threshold');
  run("navigate('sign');state.step=1;state.forms.sign['in-place']=true;render()");
  assert(!element('#app').innerHTML.includes('data-file-field="output"'));
  assert(element('#app').innerHTML.includes('已启用原地签名'));
  await listeners.click[0]({target:{closest:()=>({dataset:{action:'new-sign'}})},preventDefault(){}});
  assert.equal(run('state.step'),1);
  assert(!run('state.forms.sign.module'));
  assert(!run("state.forms.sign['append-signature']"));
  assert(element('#app').innerHTML.includes('data-file-field="output"'));
  assert(!/"(?:stdout|stderr|argv|display|path|binary)"\s*:/.test(JSON.stringify(run('state.jobs'))));
  console.log('PASS frontend: bilingual state, opaque file selection, two-step signing, mixed 3-of-3, follow-up verification, tools, in-place mode; '+replies.length+' sanitized HTTP responses');
})().catch(e=>{console.error(e);process.exitCode=1;});
