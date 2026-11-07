/* Copyright 2026 The Sigstore Authors. Apache-2.0. */
'use strict';
const $ = (s, root = document) => root.querySelector(s);
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const state = {lang:'zh', page:'sign', step:1, config:null, token:'', forms:{}, files:{}, jobs:[], active:null, picking:null, result:null, error:'', advanced:false, selectionTarget:null};
const T = (zh, en) => state.lang === 'zh' ? zh : en;
const stamp = ms => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
const defaults = () => ({sign:{algorithm:'ES256','module-version':'1','security-epoch':'0',capabilities:'0','not-before':stamp(Date.now()-60000),'not-after':stamp(Date.now()+86400000)}, verify:{}, fetch:{}, 'policy-init':{algorithms:'ES256','signature-threshold':'1','policy-version':'1','minimum-version':'1','minimum-epoch':'0',capabilities:'0','max-crl-age-seconds':'86400','max-module-bytes':'104857600'}, 'policy-update':{}});
state.forms = defaults();
const paths = {
  sign:'<path d="m14 5 5 5M4 20l4-1 12-12a2.1 2.1 0 0 0-3-3L5 16l-1 4Z"/><path d="M13 20h7"/>',
  verify:'<path d="M12 3 4 6v6c0 4 8 9 8 9s8-5 8-9V6l-8-3Z"/><path d="m8 12 3 3 5-6"/>',
  fetch:'<path d="M12 3v12m-4-4 4 4 4-4M4 16v4h16v-4"/>',
  policy:'<path d="M7 3h10l3 3v15H4V3h3ZM8 8h6m-6 4h8m-8 4h5"/>',
  update:'<path d="M4 8a8 8 0 0 1 14-3l2 3M20 3v5h-5M20 16a8 8 0 0 1-14 3l-2-3M4 21v-5h5"/>',
  folder:'<path d="M3 6h7l2 2h9v12H3V6Z"/>',
  file:'<path d="M5 3h9l5 5v13H5V3Zm9 0v6h5M8 14h8m-8 3h5"/>',
  arrow:'<path d="M4 12h16m-5-5 5 5-5 5"/>',
  chevron:'<path d="m9 5 7 7-7 7"/>',
  close:'<path d="m6 6 12 12M6 18 18 6"/>',
  copy:'<rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V3H3v13h5"/>',
  check:'<path d="m5 12 4 4L19 6"/>',
  alert:'<path d="m12 3 10 18H2L12 3Zm0 6v5m0 3h.01"/>'
};
const icon = name => `<svg class="icon" aria-hidden="true" viewBox="0 0 24 24">${paths[name] || paths.file}</svg>`;
const title = page => ({sign:T('签名','Sign'), verify:T('校验','Verify'), more:T('更多工具','More tools'), fetch:T('获取并校验','Fetch & verify'), 'policy-init':T('创建策略','Create policy'), 'policy-update':T('更新策略','Update policy')})[page];
const labels = () => ({module:T('WASM 文件','WASM file'),policy:T('信任策略','Trust policy'),output:state.page==='policy-init'?T('保存策略至','Save policy as'):T('保存文件至','Save file as'),key:T('私钥','Private key'),certificate:T('签名证书链','Signer certificate chain'),crl:T('CRL 文件','CRL file'),algorithm:T('签名算法','Algorithm'),'module-id':T('模块标识','Module ID'),'module-version':T('模块版本','Module version'),'security-epoch':T('安全纪元','Security epoch'),capabilities:T('能力位掩码','Capability mask'),'not-before':T('生效时间（UTC）','Valid from (UTC)'),'not-after':T('截止时间（UTC）','Valid until (UTC)'),'trust-root':T('根证书','Trust roots'),'state-dir':T('新状态目录','New state directory'),'additional-certificate':T('附加签名者证书','Additional signer certificates'),'signature-threshold':T('所需独立签名者数','Required distinct signers'),'policy-version':T('策略版本','Policy version'),'minimum-version':T('最低模块版本','Minimum module version'),'minimum-epoch':T('最低安全纪元','Minimum security epoch'),algorithms:T('允许的算法','Allowed algorithms'),'max-crl-age-seconds':T('CRL 最大年龄（秒）','Maximum CRL age (seconds)'),'max-module-bytes':T('模块大小上限（字节）','Maximum module size (bytes)'),url:T('HTTPS 地址','HTTPS URL')});
const errors = code => ({
  SESSION_REQUIRED:T('请重新打开终端中的会话链接。','Reopen the session link from the terminal.'),
  REQUEST_REJECTED:T('请求被拒绝，请使用本次启动的会话链接。','Request rejected. Use the current session link.'),
  INVALID_INPUT:T('请检查填写内容和选项。','Check the entered values and options.'),
  INVALID_SELECTION:T('文件选择已失效，请重新选择。','File selection has expired. Select the file again.'),
  FILE_UNAVAILABLE:T('文件不可用，请重新选择。','File unavailable. Select it again.'),
  PICKER_UNAVAILABLE:T('无法打开文件对话框。请确认服务在本机桌面运行，并已安装 Zenity 或 Tk。','Cannot open the file dialog. Run the server on your desktop with Zenity or Tk installed.'),
  BUSY:T('请先完成当前操作或文件选择。','Finish the current operation or file selection first.'),
  SESSION_FULL:T('会话已满，请重新启动服务。','Session is full. Restart the server.'),
  NOT_FOUND:T('此操作已过期，请重新选择文件。','This operation has expired. Select files again.'),
  INVALID_RESULT:T('主程序返回格式异常，未判定为成功。','Unexpected result format. Success has not been confirmed.'),
  OPERATION_FAILED:T('操作未通过。请检查文件、权限、证书有效期与策略设置。','Operation failed. Check files, permissions, certificate validity and policy settings.'),
  INTERRUPTED:T('操作中断，文件可能已写入。请在本机检查后再决定是否重试。','Operation interrupted. Files may have been written. Check them locally before retrying.'),
  CONNECTION:T('连接中断。恢复连接以确认结果，请勿重复提交。','Connection lost. Reconnect to confirm the result; do not resubmit.'),
  REQUIRED:T('请完成标记的必填项。','Complete the required fields.'),
  SIG_001:T('未找到可用签名。','No usable signature found.'),SIG_002:T('签名结构或清单无效。','Invalid signature structure or manifest.'),SIG_003:T('签名校验未通过。','Signature verification failed.'),SIG_004:T('模块内容或大小检查未通过。','Module content or size check failed.'),SIG_005:T('签名算法或密钥不符合要求。','Algorithm or key does not meet requirements.'),
  CERT_001:T('证书格式不符合要求。','Certificate format does not meet requirements.'),CERT_002:T('证书或公钥格式检查未通过。','Certificate or public-key format check failed.'),CERT_003:T('证书检查未通过。','Certificate check failed.'),CERT_004:T('文件保护或证书检查未通过。','File protection or certificate check failed.'),CERT_005:T('撤销证据检查未通过。','Revocation evidence check failed.'),CERT_006:T('签名者授权或签名门槛未满足。','Signer authorization or signature threshold not met.'),
  POL_001:T('版本回滚或本地安全状态检查未通过。','Version rollback or local security state check failed.'),POL_002:T('策略配置或更新不符合要求。','Policy configuration or update rejected.'),POL_003:T('模块权限不符合策略。','Module permissions do not meet policy.'),POL_004:T('版本、时间或回滚状态检查未通过。','Version, time or rollback state check failed.'),VM_001:T('WASM 模块不符合要求。','WASM module does not meet requirements.')
})[code] || T('请求未完成，请检查输入后重试。','Request not completed. Check the inputs before retrying.');
async function api(path, body) {
  try {
    const response = await fetch(path,{method:body===undefined?'GET':'POST',headers:{Authorization:'Bearer '+state.token,...(body===undefined?{}:{'Content-Type':'application/json'})},body:body===undefined?undefined:JSON.stringify(body),credentials:'omit',cache:'no-store',redirect:'error'});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'REQUEST_REJECTED');
    return data;
  } catch(e) {throw new Error(/^[A-Z][A-Z_0-9]+$/.test(e.message)?e.message:'CONNECTION');}
}
function toast(text) {const el=$('#toast');el.textContent=text;el.classList.add('visible');clearTimeout(toast.timer);toast.timer=setTimeout(()=>el.classList.remove('visible'),4000);}
function remember() {
  const form=$('#operation-form'); if(!form)return;
  const f=state.forms[state.page];
  for(const el of form.elements) {
    if(!el.name || el.dataset.algorithm)continue;
    if(el.type==='checkbox')f[el.name]=el.checked;
    else if(el.value==='')delete f[el.name];
    else f[el.name]=el.type==='datetime-local'?el.value+(el.value.length===16?':00':'')+'Z':el.value;
  }
  if(form.querySelector('[data-algorithm]'))f.algorithms=[...form.querySelectorAll('[data-algorithm]:checked')].map(el=>el.value).join(',');
}
const value = name => state.forms[state.page]?.[name] ?? '';
const busy = () => !!(state.active || state.picking);
function fileField(name, required=false, full=false, many=false) {
  const refs = many?(value(name)||[]):value(name)?[value(name)]:[];
  const choose = ['output','state-dir'].includes(name)?T('选择保存位置','Choose save location'):T('选择文件','Choose file');
  const selected=refs.map((id,i)=>`<span class="chosen"><span>${icon('file')}${esc(state.files[id]||T('已选文件','Selected file'))}</span><button type="button" class="icon-button" data-action="remove-file" data-field="${name}" data-index="${i}" aria-label="${esc(T('移除：','Remove: ')+(state.files[id]||labels()[name]))}" ${busy()?'disabled':''}>${icon('close')}</button></span>`).join('');
  return `<div class="field ${full?'full':''}" data-file-field="${name}"><label>${labels()[name]}${required?'<span class="required">*</span>':''}</label>${selected}<button type="button" class="file-select ${name==='module'?'module-select':''}" data-action="select-file" data-field="${name}" data-many="${many}" aria-label="${esc(choose+T('：',': ')+labels()[name])}" ${busy()||many&&refs.length>=7?'disabled':''}>${icon(name==='module'?'file':'folder')}<span>${refs.length?many?T('添加证书','Add certificate'):T('重新选择','Choose another'):choose}</span>${icon('chevron')}</button></div>`;
}
function field(name, {required=false,type='text',full=false,hint=''}={}) {
  const label=labels()[name],v=value(name);
  const attrs=`id="f-${name}" name="${name}" ${required?'required':''} autocomplete="off" spellcheck="false"`;
  let input;
  if(type==='algorithm')input=`<select ${attrs}>${['ECDSA','EdDSA','RSA'].map(group=>`<optgroup label="${group}">${state.config.algorithms.filter(a=>group==='ECDSA'?a.startsWith('ES'):group==='EdDSA'?a==='Ed25519':/^[PR]S/.test(a)).map(a=>`<option ${a===v?'selected':''}>${a}</option>`).join('')}</optgroup>`).join('')}</select>`;
  else if(type==='algorithms')input=`<div class="algorithm-picker" role="group" aria-label="${label}">${state.config.algorithms.map(a=>`<label><input type="checkbox" data-algorithm="1" value="${a}" ${String(v).split(',').includes(a)?'checked':''}>${a}</label>`).join('')}</div>`;
  else input=`<input ${attrs} type="${type==='time'?'datetime-local':type==='url'?'url':'text'}" ${type==='time'?'step="1"':''} ${type==='uint'?'inputmode="numeric" pattern="[0-9]+"':''} value="${esc(type==='time'?String(v).replace(/Z$/,''):v)}" ${name==='module-id'?'placeholder="com.example.app"':''}>`;
  return `<div class="field ${full?'full':''}"><label for="f-${name}">${label}${required?'<span class="required">*</span>':''}</label>${input}${hint?`<small>${hint}</small>`:''}</div>`;
}
const nf = (n,required=false) => field(n,{type:'uint',required});
const check = (n,label,hint='') => `<label class="check-row"><input type="checkbox" name="${n}" ${value(n)?'checked':''}><span>${label}${hint?`<small>${hint}</small>`:''}</span></label>`;
const grid = content => `<div class="form-grid">${content}</div>`;
const advanced = content => `<details class="advanced" id="advanced" ${state.advanced?'open':''}><summary>${T('高级选项','Advanced options')}</summary>${grid(content)}</details>`;
function formContent() {
  if(state.page==='sign' && state.step===1) return grid(fileField('module',true,true)+fileField('policy',true)+fileField('key',true)+fileField('certificate',true)+fileField('crl',true)+(!value('in-place')?fileField('output',true,true):`<p class="note full">${T('已启用原地签名，将写回所选 WASM 文件。','In-place signing is enabled; the selected WASM file will be replaced.')}</p>`))+advanced(check('in-place',T('原地签名','Sign in place'),T('写回原文件，不创建新的输出文件。','Replace the input file instead of creating a new output.')));
  if(state.page==='sign')return grid(field('module-id',{required:true})+nf('module-version',true)+field('algorithm',{type:'algorithm',full:true})+field('not-before',{type:'time',required:true})+field('not-after',{type:'time',required:true})+`<div class="presets full"><span>${T('有效期','Validity')}</span>${[1,7,30].map(d=>`<button type="button" data-action="validity" data-days="${d}">${d}${T(' 天',' days')}</button>`).join('')}</div>`)+advanced(`<div class="field full"><label for="f-mode">${T('签名方式','Signing mode')}</label><select id="f-mode"><option value="new" ${!value('append-signature')&&!value('replace-signature')?'selected':''}>${T('创建签名','New signature')}</option><option value="append" ${value('append-signature')?'selected':''}>${T('追加签名','Append signature')}</option><option value="replace" ${value('replace-signature')?'selected':''}>${T('替换全部签名','Replace all signatures')}</option></select></div>`+nf('security-epoch')+nf('capabilities')+check('allow-partial',T('允许多签中间文件','Allow an intermediate multisignature file'),T('未达门槛时可继续追加，不能通过完整校验。','Below quorum, add more signatures before full verification.')));
  if(state.page==='verify')return grid(fileField('module',true,true)+fileField('policy',true,true));
  if(state.page==='fetch')return grid(field('url',{type:'url',required:true,full:true})+fileField('policy',true,true)+fileField('output',true,true));
  const init=state.page==='policy-init';
  return `<p class="note">${init?T('选择新策略文件和新状态目录。','Choose a new policy file and state directory.'):T('可选项留空保持原值；填写证书或算法后替换对应集合。','Blank optional fields stay unchanged. Certificates and algorithms replace their sets.')}</p>`+grid(fileField(init?'output':'policy',true,true)+nf('policy-version',!init)+field('module-id',{required:init})+fileField('trust-root',init)+fileField('certificate',init)+(init?fileField('state-dir',true,true):'')+nf('signature-threshold')+field('algorithms',{type:'algorithms',full:true}))+advanced(fileField('additional-certificate',false,true,true)+(!init?check('clear-additional-signers',T('清除附加签名者','Clear additional signers'),T('同时调整门槛；不能同时添加证书。','Adjust the threshold too; cannot also add certificates.')):'')+nf('minimum-version')+nf('minimum-epoch')+nf('capabilities')+nf('max-crl-age-seconds')+nf('max-module-bytes'));
}
function render() {
  document.documentElement.lang=state.lang==='zh'?'zh-CN':'en-US';document.title=title(state.page)+' · WSEA Studio';
  const more=!['sign','verify'].includes(state.page);
  $('#app').innerHTML=`<div class="app-shell"><header class="topbar"><a class="brand" href="#" data-action="navigate" data-page="sign"><img src="/mark.svg" alt=""><strong>WSEA<span> Studio</span></strong></a><nav aria-label="${T('主要功能','Main navigation')}">${['sign','verify','more'].map(p=>`<button data-action="navigate" data-page="${p}" class="${(p==='more'?more:state.page===p)?'active':''}" ${(p==='more'?more:state.page===p)?'aria-current="page"':''}>${icon(p==='more'?'folder':p)}${title(p)}</button>`).join('')}</nav><button class="language" data-action="language" aria-label="${T('Switch to English','切换到中文')}">${T('EN','中文')}</button></header><main id="main"><div class="page-heading"><span class="eyebrow">WASM-COSIGN</span><h1>${title(state.page)}</h1><p>${({sign:T('为 WASM 文件添加可信签名。','Add a trusted signature to your WASM file.'),verify:T('选择文件与策略，检查签名是否有效。','Choose a file and policy to check its signatures.'),more:T('管理签名策略，或获取已签名的模块。','Manage signing policies or retrieve signed modules.'),fetch:T('通过 HTTPS 获取，校验通过后保存。','Retrieve over HTTPS and save after verification.'),'policy-init':T('设置授权签名者和校验规则。','Set authorized signers and verification rules.'),'policy-update':T('修改策略并保留已有安全状态。','Update a policy while preserving its security state.')})[state.page]}</p></div>
  ${state.page==='more'?toolsHTML():`${more?`<button class="back-link" data-action="navigate" data-page="more">← ${T('返回工具','Back to tools')}</button>`:''}${state.page==='sign'?`<div class="steps"><button data-action="step" data-step="1" ${state.step===1?'aria-current="step"':''}><span>1</span>${T('选择文件','Select files')}</button><i></i><button data-action="step" data-step="2" ${state.step===2?'aria-current="step"':''}><span>2</span>${T('签名设置','Signature settings')}</button></div>`:''}<form id="operation-form" autocomplete="off" novalidate><section class="work-card">${formContent()}</section><div id="form-error" role="alert">${state.error?`<p class="error">${errors(state.error)}</p>`:''}</div><div class="action-bar">${state.page==='sign'&&state.step===2?`<button type="button" class="secondary" data-action="step" data-step="1">${T('上一步','Back')}</button>`:`<span class="action-note">${T('* 为必填项','* Required')}</span>`}<button type="submit" class="primary" id="run-button" ${busy()?'disabled':''}>${actionLabel()}${icon('arrow')}</button></div></form>`}
  <div id="result-area" aria-live="polite">${resultHTML()}</div><details class="recent"><summary>${T('最近操作','Recent operations')} <span id="recent-count">${state.jobs.length}</span></summary><div id="history-list">${historyHTML()}</div></details><footer><span>WSEA Studio</span><span>WSEA v2</span></footer></main></div>`;
}
function toolsHTML() {return `<div class="tool-grid">${[['policy-init','policy',T('创建信任策略和多签门槛。','Create trust rules and a signature threshold.')],['policy-update','update',T('更新签名者、版本和算法。','Update signers, versions and algorithms.')],['fetch','fetch',T('下载并校验完整模块。','Download and verify a complete module.')]].map(([p,i,d])=>`<button class="tool-card" data-action="navigate" data-page="${p}">${icon(i)}<strong>${title(p)}</strong><span>${d}</span><small>${T('打开','Open')} ↗</small></button>`).join('')}</div>`;}
function actionLabel() {if(state.active)return T('正在处理…','Processing…');if(state.picking)return T('请在系统窗口中选择…','Choose in the system dialog…');return state.page==='sign'&&state.step===1?T('下一步','Next'):({sign:T('开始签名','Sign file'),verify:T('开始校验','Verify file'),fetch:T('获取并校验','Fetch & verify'),'policy-init':T('创建策略','Create policy'),'policy-update':T('保存更新','Save changes')})[state.page]||'';}
function jobLabel(j) {return ({running:T('正在处理','Processing'),partial:T('签名已添加，尚未达门槛','Signature added · more signers needed'),failed:T('操作未通过','Operation failed'),interrupted:T('操作已中断','Operation interrupted'),succeeded:j.command==='verify'?T('校验通过','Verification passed'):j.command==='sign'?T('签名完成','Signature complete'):j.command==='fetch'?T('已获取并通过校验','Retrieved and verified'):T('策略已保存','Policy saved')})[j.state];}
function resultHTML() {
  const j=state.jobs.find(j=>j.id===state.result);if(!j)return '';
  const m=j.document?.manifest, good=['succeeded','partial'].includes(j.state);
  return `<section class="result ${j.state}" id="latest-result"><div class="result-head">${j.state==='running'?'<span class="spinner"></span>':icon(good?'check':'alert')}<h2>${jobLabel(j)}</h2></div><div class="result-body">${j.error?`<p>${errors(j.error)}</p><small>${esc(j.error)}</small>`:''}${j.state==='partial'?`<p>${T('请继续添加其他授权密钥的签名。','Continue with another authorized signing key.')}</p>`:''}${m?`<dl class="result-meta"><div><dt>${T('模块','Module')}</dt><dd>${esc(m.module_id)}</dd></div><div><dt>${T('版本','Version')}</dt><dd>${esc(m.version)}</dd></div><div><dt>${T('独立签名者','Distinct signers')}</dt><dd>${m.signer_count}</dd></div></dl><div class="chips">${m.signature_algorithms.map(a=>`<span>${esc(a)}</span>`).join('')}</div>`:''}${good?`<div class="result-actions">${j.command==='sign'?`<button class="secondary" data-action="new-sign" ${busy()?'disabled':''}>${T('新的签名','New signing task')}</button>`:''}${m?`<button data-action="next-operation" data-next="append" data-id="${j.id}" class="secondary" ${busy()?'disabled':''}>${T('追加签名','Add signature')}</button>${j.command!=='verify'?`<button data-action="next-operation" data-next="verify" data-id="${j.id}" class="secondary" ${busy()?'disabled':''}>${T('校验此文件','Verify this file')}</button>`:''}`:`<button data-action="next-operation" data-next="use-policy" data-id="${j.id}" class="secondary" ${busy()?'disabled':''}>${T('用于签名','Use for signing')}</button>`}<button class="text-btn" data-action="copy-json" data-id="${j.id}">${icon('copy')}${T('复制 JSON 结果','Copy JSON result')}</button></div>`:''}</div></section>`;
}
function historyHTML() {return state.jobs.length?state.jobs.map(j=>`<button data-action="show-job" data-id="${j.id}" class="history-row"><span>${title(j.command)}</span><small class="${j.state}">${jobLabel(j)}</small>${icon('chevron')}</button>`).join(''):`<p class="muted">${T('还没有操作记录。','No operations yet.')}</p>`;}
function refresh() {$('#result-area')&&($('#result-area').innerHTML=resultHTML());$('#history-list')&&($('#history-list').innerHTML=historyHTML());$('#recent-count')&&($('#recent-count').textContent=state.jobs.length);const b=$('#run-button');if(b){b.disabled=busy();b.innerHTML=actionLabel()+icon('arrow');}document.querySelectorAll('[data-action="select-file"],[data-action="remove-file"]').forEach(b=>b.disabled=busy()||(b.dataset.many==='true'&&(value(b.dataset.field)||[]).length>=7));}
function showError(code){state.error=code;const e=$('#form-error');if(e){e.innerHTML=`<p class="error">${errors(code)}${code==='CONNECTION'?` <button class="text-btn" data-action="reconnect">${T('重新连接','Reconnect')}</button>`:''}</p>`;e.scrollIntoView({block:'nearest',behavior:'smooth'});}else toast(errors(code));}
function navigate(page){remember();state.page=page;state.error='';state.result=null;state.advanced=false;render();window.scrollTo({top:0});}
function validateFiles() {
  const f=state.forms[state.page],required={sign:['module','policy','key','certificate','crl',...(!f['in-place']?['output']:[])],verify:['module','policy'],fetch:['policy','output'],'policy-init':['output','trust-root','state-dir','certificate'],'policy-update':['policy']}[state.page]||[];
  const missing=required.filter(n=>!f[n]);document.querySelectorAll('[data-file-field]').forEach(el=>el.classList.toggle('missing',missing.includes(el.dataset.fileField)));
  if(missing.length){showError('REQUIRED');$(`[data-file-field="${missing[0]}"] button`)?.focus();return false;}return true;
}
function validateForm(){const form=$('#operation-form');const invalid=[...form.querySelectorAll('input,select')].find(el=>!el.checkValidity());if(invalid){invalid.closest('details')?.setAttribute('open','');invalid.reportValidity();return false;}return true;}
async function selectFile(field,many) {
  if(busy())return;remember();const page=state.page;state.selectionTarget={page,field,many};state.picking='starting';refresh();
  try {const s=await api('/api/selections',{command:page,field,language:state.lang});state.picking=s.id;pollSelection(s.id,{page,field,many});toast(T('请在系统文件窗口中选择。','Choose a file in the system dialog.'));}
  catch(e){state.picking=null;refresh();showError(e.message);}
}
async function pollSelection(id,target) {
  try {const s=await api('/api/selections/'+id);if(s.state==='picking'){setTimeout(()=>pollSelection(id,target),400);return;}state.picking=null;state.selectionTarget=null;
    if(s.state==='selected'&&target){remember();state.files[s.file.id]=s.file.name;const f=state.forms[target.page];f[target.field]=target.many?[...(f[target.field]||[]),s.file.id]:s.file.id;state.error='';render();$(`[data-file-field="${target.field}"] button`)?.focus();}
    else{refresh();if(s.state==='failed')showError(s.error);}
  }catch(e){showError(e.message);refresh();}}
async function launch() {
  if(busy())return;remember();if(!validateFiles()||!validateForm())return;
  if(state.page==='sign'&&state.step===1){state.step=2;state.error='';render();$('#f-module-id')?.focus();return;}
  const fields={...state.forms[state.page]};if(fields['in-place'])delete fields.output;
  state.error='';state.active='submitting';refresh();$('#form-error').textContent='';
  try {const j=await api('/api/jobs',{command:state.page,fields});state.jobs.unshift(j);state.jobs=state.jobs.slice(0,20);state.active=j.id;state.result=j.id;refresh();$('#latest-result')?.scrollIntoView({block:'nearest',behavior:'smooth'});poll(j.id);}
  catch(e){if(e.message!=='CONNECTION')state.active=null;refresh();showError(e.message);}
}
async function poll(id) {
  try {const j=await api('/api/jobs/'+id);state.jobs=state.jobs.map(old=>old.id===id?j:old);if(j.state!=='running')state.active=null;refresh();if(j.state==='running')setTimeout(()=>poll(id),500);}
  catch(e){showError(e.message);}
}
async function nextOperation(id,action) {
  if(busy())return;
  try {remember();const next=await api('/api/jobs/'+id+'/next',{action});Object.assign(state.files,next.files);state.forms[next.command]=action==='use-policy'?{...state.forms.sign,...next.fields}:next.fields;state.page=next.command;state.step=1;state.advanced=action==='append';state.result=null;state.error='';render();window.scrollTo({top:0});}
  catch(e){showError(e.message);}
}
function connectionScreen(code='') {
  document.documentElement.lang=state.lang==='zh'?'zh-CN':'en-US';
  $('#app').innerHTML=`<main class="connection"><section class="work-card"><button class="language" data-action="language-connect">${T('EN','中文')}</button><img src="/mark.svg" alt=""><h1>WSEA Studio</h1><p>${T('使用本次启动的会话链接，或输入会话令牌。','Use the current session link or enter the session token.')}</p><form id="connect-form"><label for="session-token">${T('会话令牌','Session token')}</label><input id="session-token" type="password" required autocomplete="off"><button class="primary">${T('连接','Connect')}${icon('arrow')}</button></form>${code?`<p class="error">${errors(code)}</p>`:''}</section></main>`;
}
async function connect(token) {state.token=token;try{state.config=await api('/api/config');state.jobs=state.config.jobs;state.active=state.config.active_job;state.picking=state.config.selection;render();if(state.active){state.result=state.active;refresh();poll(state.active);}if(state.picking)pollSelection(state.picking,null);}catch(e){state.config=null;connectionScreen(e.message);}}
document.addEventListener('submit',e=>{e.preventDefault();if(e.target.id==='connect-form')connect($('#session-token').value.trim());else if(e.target.id==='operation-form')launch();});
document.addEventListener('input',e=>{if(e.target.closest('#operation-form'))remember();});
document.addEventListener('change',e=>{if(e.target.name==='in-place'){remember();render();}if(e.target.id==='f-mode'){remember();state.forms.sign['append-signature']=e.target.value==='append';state.forms.sign['replace-signature']=e.target.value==='replace';}});
document.addEventListener('toggle',e=>{if(e.target.id==='advanced')state.advanced=e.target.open;},true);
document.addEventListener('click',async e=>{
  const b=e.target.closest('[data-action]');if(!b)return;e.preventDefault();const a=b.dataset.action;
  if(a==='navigate')navigate(b.dataset.page);
  else if(a==='reconnect'){try{const c=await api('/api/config');state.jobs=c.jobs;state.active=c.active_job;state.picking=c.selection;state.error='';if(state.result&&!state.jobs.some(j=>j.id===state.result))state.result=null;render();if(state.active)poll(state.active);if(state.picking)pollSelection(state.picking,state.selectionTarget);}catch(e){showError(e.message);}}
  else if(a==='language'||a==='language-connect'){remember();state.lang=state.lang==='zh'?'en':'zh';state.config?render():connectionScreen();}
  else if(a==='step'){remember();if(Number(b.dataset.step)===2&&!validateFiles())return;state.step=Number(b.dataset.step);state.error='';render();}
  else if(a==='select-file')selectFile(b.dataset.field,b.dataset.many==='true');
  else if(a==='remove-file'){remember();const f=state.forms[state.page],v=f[b.dataset.field];if(Array.isArray(v))v.splice(Number(b.dataset.index),1);else delete f[b.dataset.field];render();}
  else if(a==='validity'){remember();state.forms.sign['not-before']=stamp(Date.now()-60000);state.forms.sign['not-after']=stamp(Date.now()+Number(b.dataset.days)*86400000);render();}
  else if(a==='new-sign'){remember();state.forms.sign=defaults().sign;state.step=1;state.advanced=false;state.page='sign';state.error='';state.result=null;render();window.scrollTo({top:0});}
  else if(a==='show-job'){state.result=b.dataset.id;refresh();$('#latest-result')?.scrollIntoView({block:'nearest',behavior:'smooth'});}
  else if(a==='next-operation')nextOperation(b.dataset.id,b.dataset.next);
  else if(a==='copy-json'){const j=state.jobs.find(j=>j.id===b.dataset.id);try{await navigator.clipboard.writeText(JSON.stringify(j.document,null,2));toast(T('已复制 JSON 结果','JSON result copied'));}catch{toast(T('浏览器未允许复制。','Clipboard access unavailable.'));}}
});
const token=new URLSearchParams(location.hash.slice(1)).get('token');
if(location.hash)history.replaceState(null,'',location.pathname);
if(token)connect(token);else connectionScreen();
