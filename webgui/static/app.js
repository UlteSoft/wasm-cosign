/* Copyright 2026 The Sigstore Authors. Apache-2.0. No external dependencies. */
'use strict';
const $ = (selector, root = document) => root.querySelector(selector);
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const state = {lang: 'zh', page: 'sign', config: null, token: '', forms: {}, jobs: [], active: null, result: null, mode: 'new', error: '', preview: ''};
const T = (zh, en) => state.lang === 'zh' ? zh : en;
const stamp = ms => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
const defaults = () => ({
  sign: {'algorithm':'ES256','module-version':'1','security-epoch':'0','capabilities':'0','not-before':stamp(Date.now()-60000),'not-after':stamp(Date.now()+86400000)},
  verify:{},fetch:{},'policy-init':{'algorithms':'ES256','signature-threshold':'1','policy-version':'1','minimum-version':'1','minimum-epoch':'0','capabilities':'0','max-crl-age-seconds':'86400','max-module-bytes':'104857600'},'policy-update':{},help:{topic:'secure'}
});
state.forms = defaults();
const paths = {
  sign:'<path d="m14 5 5 5M4 20l4-1 12-12a2.1 2.1 0 0 0-3-3L5 16l-1 4Z"/><path d="M13 20h7"/>',
  verify:'<path d="M12 3 4 6v6c0 4 8 9 8 9s8-5 8-9V6l-8-3Z"/><path d="m8 12 3 3 5-6"/>',
  fetch:'<path d="M12 3v12m-4-4 4 4 4-4M4 16v4h16v-4"/>',
  policy:'<path d="M7 3h10l3 3v15H4V3h3ZM8 8h6m-6 4h8m-8 4h5"/>',
  update:'<path d="M4 8a8 8 0 0 1 14-3l2 3M20 3v5h-5M20 16a8 8 0 0 1-14 3l-2-3M4 21v-5h5"/>',
  history:'<path d="M3 11a9 9 0 1 1 2 7M3 4v7h7m2-4v6l4 2"/>',
  help:'<circle cx="12" cy="12" r="9"/><path d="M9 9a3 3 0 0 1 6 0c0 2-3 2-3 4m0 4h.01"/>',
  folder:'<path d="M3 6h7l2 2h9v12H3V6Z"/>',
  file:'<path d="M5 3h9l5 5v13H5V3Zm9 0v6h5M8 14h8m-8 3h5"/>',
  arrow:'<path d="M4 12h16m-5-5 5 5-5 5"/>',
  chevron:'<path d="m9 5 7 7-7 7"/>',
  close:'<path d="m6 6 12 12M6 18 18 6"/>',
  up:'<path d="M12 20V4m-7 7 7-7 7 7"/>',
  lock:'<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2"/>',
  terminal:'<path d="m5 7 5 5-5 5m8 0h6"/>',
  copy:'<rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V3H3v13h5"/>',
  check:'<path d="m5 12 4 4L19 6"/>',
  alert:'<path d="m12 3 10 18H2L12 3Zm0 6v5m0 3h.01"/>',
  key:'<circle cx="8" cy="8" r="5"/><path d="m12 12 9 9m-6-6 3-3m0 6 3-3"/>',
  globe:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a18 18 0 0 0 0 18 18 18 0 0 0 0-18Z"/>'
};
const icon = name => `<svg class="icon" aria-hidden="true" viewBox="0 0 24 24">${paths[name] || paths.file}</svg>`;
const nav = () => [
  ['sign','sign',T('签名工作台','Sign workspace')],['verify','verify',T('验证模块','Verify module')],['fetch','fetch',T('安全获取','Secure fetch')],
  ['policy-init','policy',T('创建信任策略','Create policy')],['policy-update','update',T('更新信任策略','Update policy')],['history','history',T('操作记录','Session activity')],['help','help',T('帮助与环境','Help & environment')]
];
const title = command => nav().find(n => n[0] === command)?.[2] || T('版本信息','Version');
const actionLabel = () => ({sign:T('生成 WSEA 签名','Create WSEA signature'),verify:T('验证此模块','Verify module'),fetch:T('获取并验证','Fetch & verify'),'policy-init':T('创建信任策略','Create trust policy'),'policy-update':T('保存策略更新','Apply policy update'),help:T('查看命令帮助','Read CLI help')})[state.page];
const descriptions = () => ({
  sign:T('创建签名，或向已有模块追加签名。','Create a signature or add another signer to a module.'),
  verify:T('检查完整模块、签名门槛、证书链、CRL 与本机回滚状态。','Check the exact module, signature quorum, certificate chain, CRLs and local rollback state.'),
  fetch:T('通过 HTTPS 获取模块。仅在 TLS 与完整 WSEA 验证通过后保存。','Retrieve a module over HTTPS. Save only after TLS and complete WSEA verification succeed.'),
  'policy-init':T('建立本地信任锚、授权签名者与初始回滚状态。','Establish local trust anchors, authorized signers and initial rollback state.'),
  'policy-update':T('更新授权规则，保留已有回滚状态。仅提交你明确填写的修改。','Update authorization while preserving rollback state. Only explicitly filled fields are submitted.'),
  history:T('最近 20 次操作，重启服务后清空。','The last 20 operations, cleared when the server restarts.'),
  help:T('查看命令用法、版本和程序路径。','View command usage, version and executable path.')
});

async function api(path, body) {
  const response = await fetch(path, {method: body === undefined ? 'GET' : 'POST', headers:{Authorization:'Bearer '+state.token,...(body === undefined ? {} : {'Content-Type':'application/json'})}, body:body === undefined ? undefined : JSON.stringify(body), credentials:'omit',cache:'no-store',redirect:'error'});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}
function toast(message) { const el = $('#toast'); el.textContent = message; el.classList.add('visible'); clearTimeout(toast.timer); toast.timer=setTimeout(()=>el.classList.remove('visible'),3500); }
async function copy(text) { try {await navigator.clipboard.writeText(text);toast(T('已复制','Copied'));} catch {toast(T('浏览器不允许复制，请手动选择文本。','Clipboard unavailable. Select and copy the text manually.'));} }
function remember() {
  const form = $('#operation-form'); if (!form) return;
  const values = {};
  for (const el of form.elements) {
    if (!el.name || el.disabled || el.dataset.algorithm) continue;
    if (el.type === 'checkbox') {if (el.checked) values[el.name] = true;}
    else if (el.name === 'additional-certificate') {const lines=el.value.split('\n').map(s=>s.trim()).filter(Boolean);if(lines.length)values[el.name]=lines;}
    else if (el.value !== '') values[el.name] = el.value;
  }
  const algorithms = [...form.querySelectorAll('[data-algorithm]:checked')].map(el=>el.value);
  if (algorithms.length) values.algorithms=algorithms.join(',');
  if (state.page === 'sign') {
    if (state.mode === 'append') values['append-signature'] = true;
    if (state.mode === 'replace') values['replace-signature'] = true;
  }
  state.forms[state.page] = values;
}
function value(name) {return state.forms[state.page]?.[name] ?? '';}
const hints = () => ({
  module:T('现有 .wasm 文件的绝对路径。','Absolute path to an existing .wasm file.'),
  policy:T('选择现有策略文件。','Select an existing policy file.'),
  key:T('选择与算法匹配的 PEM 私钥。','Select a PEM private key matching the algorithm.'),
  certificate:T('PEM：叶证书在前，中间证书依次在后。','PEM: leaf certificate first, followed by intermediates.'),
  crl:T('选择完整且有效的 CRL 包。','Select a complete, valid CRL bundle.'),
  'additional-certificate':T('每行一个绝对路径，最多 7 个；更新时将替换全部附加签名者。','One absolute path per line, up to 7. An update replaces the entire additional signer set.'),
  'signature-threshold':T('不同授权公钥的数量，范围 1–8。重复密钥不计数。','Number of distinct authorized public keys, 1–8. Duplicate keys do not count.'),
  'not-before':T('RFC3339 时间，Z 表示 UTC。','RFC3339 timestamp. Z denotes UTC.'),
  'not-after':T('追加多签时，所有清单字段必须完全一致。','When appending, all manifest fields must match exactly.'),
  'state-dir':T('新的本地受保护目录；已有安全状态不能重置。','New protected local directory. Existing security state cannot be reset.'),
  'trust-root':T('PEM 格式的可信 CA 证书。','Trusted CA certificates in PEM format.'),
  capabilities:T('取值范围 0–63。','Range: 0–63.'),
  'policy-version':state.page==='policy-update'?T('必须严格大于当前策略版本。','Must be strictly greater than the current policy version.'):T('初始化策略版本，通常为 1。','Initial policy version, usually 1.'),
  algorithms:state.page==='policy-update'?T('全部不选则保持原值；选择后替换允许集合。','Leave all unchecked to keep the current value. A selection replaces the allowed set.'):T('仅允许这里选中的算法；默认 ES256。','Only selected algorithms are allowed; ES256 is the default.'),
  'max-crl-age-seconds':T('已认证 CRL 的最大允许年龄（秒）。','Maximum age of an authenticated CRL, in seconds.'),
  'max-module-bytes':T('含签名的完整模块大小上限（字节）。','Size limit of the complete signed module, in bytes.'),
  url:T('完整 .wasm 模块的 HTTPS 地址。','HTTPS URL of the complete .wasm module.')
});
const labels = () => ({
  module:T('WASM 模块','WASM module'),policy:T('信任策略','Trust policy'),output:state.page==='policy-init'?T('新策略文件','New policy file'):T('输出文件','Output file'),key:T('私钥文件','Private key file'),certificate:T('签名证书链','Signer certificate chain'),crl:T('CRL 证据包','CRL evidence bundle'),algorithm:T('签名算法','Signature algorithm'),'module-id':T('模块标识','Module ID'),'module-version':T('模块版本','Module version'),'security-epoch':T('安全纪元','Security epoch'),capabilities:T('能力位掩码','Capability mask'),'not-before':T('生效时间 · UTC','Valid from · UTC'),'not-after':T('截止时间 · UTC','Valid until · UTC'),'trust-root':T('信任根证书','Trust root'),'state-dir':T('回滚状态目录','Rollback state directory'),'additional-certificate':T('附加签名者证书','Additional signer certificates'),'signature-threshold':T('多签门槛','Signature threshold'),'policy-version':T('策略版本','Policy version'),'minimum-version':T('最低模块版本','Minimum module version'),'minimum-epoch':T('最低安全纪元','Minimum security epoch'),algorithms:T('允许的算法','Allowed algorithms'),'max-crl-age-seconds':T('CRL 最大年龄','Maximum CRL age'),'max-module-bytes':T('模块大小上限','Maximum module size'),url:T('模块 HTTPS 地址','Module HTTPS URL'),topic:T('命令主题','Command topic')
});
function field(name, {type='text',required=false,full=false,placeholder='',hint=true}={}) {
  const id='f-'+name, current=value(name), label=labels()[name];
  const optional=state.page==='policy-update'&&!required?`<span class="optional">${T('留空保持原值','blank = unchanged')}</span>`:'';
  const props=`id="${id}" name="${name}" ${required?'required':''} autocomplete="off" spellcheck="false"`;
  let control;
  if (type==='algorithm') {
    const families=[['ECDSA',['ES256','ESP256','ES384','ESP384','ES512','ESP512']],['EdDSA',['Ed25519']],['RSA-PSS',['PS256','PS384','PS512']],['RSA PKCS#1 v1.5',['RS256','RS384','RS512']]];
    control=`<select ${props}>${families.map(([title,items])=>`<optgroup label="${title}">${items.map(a=>`<option ${current===a?'selected':''}>${a}</option>`).join('')}</optgroup>`).join('')}</select>`;
  } else if(type==='algorithms') {
    const chosen=String(current).split(',');
    control=`<div class="algorithm-picker" role="group" aria-labelledby="label-${name}">${state.config.algorithms.map(a=>`<label><input type="checkbox" data-algorithm="true" value="${a}" ${chosen.includes(a)?'checked':''}>${a}</label>`).join('')}</div>`;
  } else if(type==='paths') {
    control=`<textarea ${props} placeholder="/path/to/second-signer.pem\n/path/to/third-signer.pem">${esc(Array.isArray(current)?current.join('\n'):current)}</textarea><button type="button" class="text-btn" data-action="browse" data-field="${name}" data-kind="paths">${icon('folder')}${T('添加证书路径','Add certificate path')}</button>`;
  } else if(type==='path'||type==='directory'||type==='output') {
    control=`<div class="path-control"><input ${props} value="${esc(current)}" placeholder="${esc(placeholder||'/absolute/path/'+(name==='module'?'module.wasm':name==='output'?'signed.wasm':name==='policy'?'policy':name==='key'?'signer.key':name==='crl'?'bundle.crl.pem':name==='state-dir'?'state':name==='trust-root'?'root.pem':'signer.pem'))}"><button type="button" class="browse-btn" aria-label="${esc(T('选择路径：','Choose path: ')+label)}" data-action="browse" data-field="${name}" data-kind="${type}">${icon('folder')}</button></div>`;
  } else {
    control=`<input ${props} value="${esc(current)}" placeholder="${esc(placeholder)}" ${type==='uint'?'inputmode="numeric" pattern="[0-9]+"':''} type="${type==='url'?'url':'text'}">`;
  }
  return `<div class="field ${full?'full':''}" data-field-row="${name}"><label id="label-${name}" ${type==='algorithms'?'':`for="${id}"`}>${esc(label)}${required?'<span class="required" aria-hidden="true">*</span>':''}${optional}</label>${control}${hint&&hints()[name]?`<p class="field-hint">${hints()[name]}</p>`:''}</div>`;
}
function check(name, label, hint) {return `<div class="check-row"><input type="checkbox" id="f-${name}" name="${name}" ${value(name)?'checked':''}><label for="f-${name}">${label}<small>${hint}</small></label></div>`;}
function section(number, heading, fields, tag='') {return `<section class="section-card"><div class="section-head"><span class="section-number">${number}</span><h2>${heading}</h2>${tag?`<span class="tail">${tag}</span>`:''}</div><div class="form-grid">${fields}</div></section>`;}
function note(text,warning=false) {return `<div class="note ${warning?'warning':''}">${icon(warning?'alert':'verify')}<span>${text}</span></div>`;}
const pf=(name,required=false,full=false,type='path')=>field(name,{type,required,full});
const nf=(name,required=false)=>field(name,{type:'uint',required});
function formContent() {
  if(state.page==='sign') return `
    <div class="mode-tabs" role="group" aria-label="${T('签名方式','Signing mode')}">${[['new',T('创建签名','New signature')],['append',T('追加多签','Append signature')],['replace',T('替换签名','Replace signatures')]].map(([m,l])=>`<button type="button" data-action="mode" data-mode="${m}" aria-pressed="${state.mode===m}" class="${state.mode===m?'selected':''}">${l}</button>`).join('')}</div>
    ${state.mode==='append'?note(T('保留已有签名。请选择另一授权密钥，并保持清单字段一致。','Keep existing signatures. Choose another authorized key and retain the same manifest.')):state.mode==='replace'?note(T('将替换模块中全部已有签名。','Replaces all existing signatures in the module.'),true):''}
    ${section('01',T('文件与策略','Files & policy'),pf('module',true,true)+pf('policy',true,true)+check('in-place',T('原地替换输入文件','Replace the input file in place'),T('直接写回原文件。关闭时保存到新文件。','Write back to the input. Otherwise, save to a new file.'))+pf('output',!value('in-place'),true,'output'),'WASM / WSEA v2')}
    ${section('02',T('签名身份','Signing identity'),field('algorithm',{type:'algorithm',required:true})+'<p class="algorithm-note">'+T('ECDSA · Ed25519 · RSA','ECDSA · Ed25519 · RSA')+'</p>'+pf('key',true,true)+pf('certificate',true)+pf('crl',true),'LOCAL KEY')}
    ${section('03',T('签名清单','Signed manifest'),field('module-id',{required:true,placeholder:'com.example.app'})+nf('module-version',true)+nf('security-epoch')+nf('capabilities')+field('not-before',{required:true})+field('not-after',{required:true})+check('allow-partial',T('允许输出尚未达到门槛的多签中间文件','Allow an intermediate signature below quorum'),T('未达门槛时保存中间文件，供后续追加签名。','Save an intermediate file below quorum to collect more signatures.')))}`;
  if(state.page==='verify') return section('01',T('选择待验证模块','Choose a module to verify'),pf('module',true,true)+pf('policy',true,true),'OFFLINE')+note(T('所有签名有效且满足策略门槛时，验证通过。','Verification requires valid signatures meeting the policy threshold.'));
  if(state.page==='fetch') return section('01',T('可信模块来源','Module source'),field('url',{type:'url',required:true,full:true,placeholder:'https://example.com/releases/module.wasm'})+pf('policy',true,true)+pf('output',true,true,'output'),'HTTPS + WSEA')+note(T('验证通过后保存到新文件，不覆盖已有文件。','Save to a new file after verification; existing files are not overwritten.'));
  if(state.page==='policy-init'||state.page==='policy-update') {
    const init=state.page==='policy-init';
    return (!init?note(T('留空保持原值；填写附加证书或选择算法会替换对应集合。','Blank fields stay unchanged. Certificates and algorithms replace their respective sets.')):note(T('请选择新的策略文件和状态目录。已有状态不会被重置。','Choose a new policy file and state directory. Existing state will not be reset.')))+
    section('01',T('本地信任配置','Local trust configuration'),(init?pf('output',true,true,'output'):pf('policy',true,true))+nf('policy-version',!init)+pf('trust-root',init)+ (init?pf('state-dir',true,true,'directory'):''),'LOCAL TRUST')+
    section('02',T('模块与授权签名者','Module & authorized signers'),field('module-id',{required:init,full:true,placeholder:'com.example.app'})+pf('certificate',init,true)+field('additional-certificate',{type:'paths',full:true})+(!init?check('clear-additional-signers',T('清除所有附加签名者','Clear all additional signers'),T('不能同时填写附加证书；门槛必须与剩余签名者数量兼容。','Cannot be combined with additional certificates. The threshold must fit the remaining signers.')):'')+nf('signature-threshold')+nf('minimum-version')+nf('minimum-epoch')+nf('capabilities')+field('algorithms',{type:'algorithms',full:true}),'1–8 SIGNERS')+
    section('03',T('验证资源限制','Verification limits'),nf('max-crl-age-seconds')+nf('max-module-bytes'),'POLICY LIMITS');
  }
  if(state.page==='help') return `
    ${section('01',T('主程序帮助','Native CLI reference'),`<div class="field full"><label for="f-topic">${labels().topic}</label><select id="f-topic" name="topic">${['root','secure','sign','verify','fetch','policy-init','policy-update'].map(t=>`<option value="${t}" ${value('topic')===t?'selected':''}>${t==='root'?'cosign':t==='secure'?'wasm secure':t}</option>`).join('')}</select></div>`)}
    ${section('02',T('当前运行环境','Current environment'),`<div class="field full"><label>${T('二进制路径','Binary path')}</label><pre class="output">${esc(state.config.binary)}</pre><label>${T('版本','Version')}</label><p class="mono">${esc(state.config.version)}</p><button class="text-btn" data-action="version" type="button">${icon('update')}${T('重新查询版本','Query version again')}</button><p class="field-hint">${T('命令时限','Command timeout')}: ${state.config.timeout}s · ${T('文件选择器根目录','File-picker roots')}: ${esc(state.config.browse_roots.join(' · '))}</p></div>`)} `;
  return '';
}
function render() {
  document.documentElement.lang=state.lang==='zh'?'zh-CN':'en-US';
  document.title=title(state.page)+' · WSEA Studio';
  const items=nav();
  $('#app').innerHTML=`<div class="shell"><aside class="sidebar">
    <div class="brand"><img src="/mark.svg" alt=""><div><strong>WSEA Studio</strong><small>LOCAL SIGNING SUITE</small></div></div>
    <div><div class="nav-label">${T('工作空间','WORKSPACE')}</div><nav class="nav" aria-label="${T('功能导航','Tools')}">${items.slice(0,5).map(navButton).join('')}</nav></div>
    <div><div class="nav-label">${T('会话与工具','SESSION & TOOLS')}</div><nav class="nav secondary" aria-label="${T('会话导航','Session')}">${items.slice(5).map(navButton).join('')}</nav></div>
    <div class="sidebar-bottom"><div class="connected"><span class="dot"></span>${T('本机二进制已连接','Local binary connected')}</div><div class="binary-label">wasm-cosign</div><div class="version">${esc(state.config.version.replace(/^wasm-cosign /,''))}</div></div>
  </aside><div class="workspace"><header class="topbar"><div class="breadcrumb"><span>WORKSPACE</span><span>/</span><strong>${title(state.page)}</strong></div><div class="top-actions"><span class="local-badge">${icon('lock')}127.0.0.1 <span class="dot"></span></span><button class="language" data-action="language" aria-label="${T('Switch to English','切换到中文')}">${T('EN / 中','中 / EN')}</button></div></header>
  <main id="main"><div class="page-heading"><div><div class="eyebrow">WASM-COSIGN</div><h1>${title(state.page)}</h1><p class="subtitle">${descriptions()[state.page]}</p></div><div class="protocol-tag">${icon('verify')}WSEA v2</div></div>
  ${state.page==='history'?`<div id="history-list">${historyHTML()}</div><div id="result-area">${resultHTML()}</div>`:`<div class="layout"><div class="left-column"><form id="operation-form" autocomplete="off">${formContent()}</form><div id="form-error" role="alert">${state.error?`<div class="error">${esc(state.error)}</div>`:''}</div><div id="result-area" aria-live="polite">${resultHTML()}</div></div>${railHTML()}</div>`}
  <footer class="page-footer"><span>WSEA Studio · wasm-cosign</span><span>${T('本地工作区','Local workspace')}</span></footer></main></div></div>`;
  toggleInPlace();
}
function navButton([id,name,label]) {return `<button type="button" data-action="navigate" data-page="${id}" class="${state.page===id?'active':''}" ${state.page===id?'aria-current="page"':''}>${icon(name)}<span>${label}</span></button>`;}
function railHTML() {return `<aside class="side-panel"><div class="summary-card"><div class="summary-top"><div class="mini-label">OPERATION OVERVIEW</div><div class="summary-title">${icon(state.page==='sign'?'sign':state.page==='verify'?'verify':state.page==='fetch'?'globe':'policy')}${T('本次操作','This operation')}</div><dl class="summary-list" id="summary-list">${summaryHTML()}</dl></div><div class="summary-bottom"><button type="submit" form="operation-form" class="run-btn" id="run-button" ${state.active?'disabled':''}>${state.active?'<span class="spinner" aria-hidden="true"></span>'+T('正在执行…','Running…'):actionLabel()+icon('arrow')}</button><button class="preview-btn" type="button" data-action="preview">${icon('terminal')}${T('预览实际命令','Preview actual command')}</button><pre class="preview-box" id="command-preview" ${state.preview?'':'hidden'}>${esc(state.preview)}</pre></div></div>
  </aside>`;}
function summaryHTML() {
  const f=state.forms[state.page]||{}, rows=[];
  rows.push([T('对象','Target'),'WebAssembly']);
  if(state.page==='sign') {
    rows.push([T('算法','Algorithm'),f.algorithm||'ES256']);
    rows.push([T('模式','Mode'),state.mode==='append'?T('追加多签','Append'):state.mode==='replace'?T('替换签名','Replace'):T('创建签名','New signature')]);
    rows.push([T('输出','Output'),f['in-place']?T('原地原子替换','Atomic in-place'):T('新文件','New file')]);
    rows.push([T('签名门槛','Quorum'),f['allow-partial']?T('允许中间文件','Partial allowed'):T('必须完整满足','Full quorum required')]);
  } else if(state.page==='verify'||state.page==='fetch') rows.push([T('签名门槛','Quorum'),T('必须完整满足','Full quorum required')]);
  else if(state.page.startsWith('policy')) {rows.push([T('策略版本','Policy version'),f['policy-version']||'—']);rows.push([T('状态','State'),state.page==='policy-init'?T('创建新状态','Create new state'):T('保留现有状态','Preserve existing state')]);}
  rows.push([T('网络','Network'),state.page==='fetch'?'HTTPS':T('离线','Offline')]);
  return rows.map(([k,v])=>`<div class="summary-row"><dt>${k}</dt><dd>${esc(v)}</dd></div>`).join('');
}
function toggleInPlace() {
  if(state.page!=='sign')return;
  const box=$('#f-in-place'), input=$('#f-output'), row=$('[data-field-row="output"]');
  if(box&&input){row.hidden=box.checked;input.disabled=box.checked;input.required=!box.checked;}
}
function navigate(page) {remember();state.page=page;state.error='';state.preview='';state.result=null;render();window.scrollTo({top:0});}
function jobLabel(job) {
  if(job.state==='succeeded') return ['verify','sign','fetch'].includes(job.command)?T('完整验签通过','Full verification passed'):T('操作已完成','Operation completed');
  return ({running:T('正在执行','Running'),partial:T('中间签名 · 尚未达门槛','Partial signature · quorum incomplete'),failed:T('操作未通过','Operation did not pass'),interrupted:T('操作中断 · 请检查本地状态','Interrupted · inspect local state')})[job.state]||job.state;
}
function resultHTML() {
  const job=state.jobs.find(j=>j.id===state.result);if(!job)return '';
  const running=job.state==='running', m=job.document?.manifest, symbol=running?'<span class="spinner"></span>':icon(job.state==='succeeded'?'check':job.state==='partial'?'history':'alert');
  let subtitle=running?T('正在处理，请稍候。','Processing. Please wait.'):job.state==='partial'?T('尚未满足签名门槛，请继续追加其他授权密钥的签名。','Quorum is incomplete. Add signatures from other authorized keys.'):job.state==='interrupted'?T('中断时可能已有文件写入。检查输出与策略状态后再决定是否重试。','Files may already have been written. Inspect outputs and policy state before deciding to retry.'):`${title(job.command)} · ${job.seconds}s · exit ${job.exit_code ?? '—'}`;
  const artifact=job.fields.output||job.fields.module;
  let body='';
  if(m){
    const signers=m.signer_spkis||[],algs=m.signature_algorithms||[m.algorithm];
    body+=`<div class="result-meta"><div><small>${T('模块标识','Module ID')}</small><strong>${esc(m.module_id)}</strong></div><div><small>${T('模块版本','Module version')}</small><strong class="mono">${esc(m.version)}</strong></div><div><small>${T('独立签名者','Distinct signers')}</small><strong>${signers.length}</strong></div></div><p class="field-hint">${T('签名贡献的算法','Contribution algorithms')}: ${esc(algs.join(' · '))}</p>${signers.map((s,i)=>`<div class="signer-row"><span class="chip">KEY ${String(i+1).padStart(2,'0')}</span><code>SPKI ${esc(s)}</code></div>`).join('')}`;
    if(artifact)body+=`<p class="field-hint">${T('模块路径','Module path')} · <span class="mono">${esc(artifact)}</span></p>`;
    if(job.command==='sign')body+=`<div class="result-actions"><button type="button" class="text-btn" data-action="continue-sign" data-id="${job.id}">${icon('sign')}${T('继续追加另一签名','Append another signature')}</button><button type="button" class="text-btn" data-action="verify-artifact" data-id="${job.id}">${icon('verify')}${T('转到完整验签','Open full verification')}</button></div>`;
  }
  if(job.protocol_error)body+=`<div class="error">${esc(job.protocol_error)}</div>`;
  if(!running){body+=`<details ${job.state==='failed'||job.state==='interrupted'||!m?'open':''}><summary>${T('主程序原始输出','Raw CLI output')}</summary><pre class="output">${esc((job.stdout||'')+(job.stderr?'\n'+job.stderr:''))||T('（无输出）','(No output)')}</pre></details><details><summary>${T('实际命令与完整清单','Actual command & full manifest')}</summary><pre class="output">${esc(job.display)}</pre>${m?`<pre class="output">${esc(JSON.stringify(m,null,2))}</pre>`:''}</details><button type="button" class="text-btn" data-action="copy-result" data-id="${job.id}">${icon('copy')}${T('复制结果','Copy result')}</button>`;}
  return `<section class="result ${job.state}" id="latest-result"><div class="result-head">${symbol}<div><strong>${jobLabel(job)}</strong><small>${subtitle}</small></div></div>${body?`<div class="result-body">${body}</div>`:''}</section>`;
}
function historyHTML(){return state.jobs.length?state.jobs.map(j=>`<button class="history-row ${j.state}" data-action="show-job" data-id="${j.id}">${icon(j.state==='succeeded'?'check':j.state==='failed'?'alert':'history')}<span><strong>${title(j.command)}</strong><small>${new Date(j.started*1000).toLocaleTimeString(state.lang==='zh'?'zh-CN':'en-US')} · ${esc(j.fields['module-id']||j.fields.module?.split(/[\\/]/).pop()||j.command)}</small></span><span class="history-status">${jobLabel(j)}</span></button>`).join(''):`<div class="empty-state">${icon('history')}<h2>${T('从一份可信签名开始','Start with a trusted signature')}</h2>${T('完成一次操作后，结果会出现在这里。','Your operations will appear here once you run a command.')}</div>`;}
function refreshResult() {const target=$('#result-area');if(target)target.innerHTML=resultHTML();const history=$('#history-list');if(history)history.innerHTML=historyHTML();const run=$('#run-button');if(run){run.disabled=!!state.active;run.innerHTML=state.active?'<span class="spinner"></span>'+T('正在执行…','Running…'):actionLabel()+icon('arrow');}}
function showError(message){state.error=message;const el=$('#form-error');if(el){el.innerHTML=`<div class="error">${esc(message)}</div>`;el.scrollIntoView({block:'nearest',behavior:'smooth'});}else toast(message);}
async function launch(command=state.page, fields=state.forms[state.page]) {
  if(state.active)return;
  state.active='submitting';state.error='';refreshResult();if($('#form-error'))$('#form-error').textContent='';
  try{
    const job=await api('/api/jobs',{command,fields});state.jobs.unshift(job);state.jobs=state.jobs.slice(0,20);state.active=job.id;state.result=job.id;refreshResult();$('#latest-result')?.scrollIntoView({block:'nearest',behavior:'smooth'});poll(job.id);
  }catch(error){state.active=null;refreshResult();showError(error.message);}
}
async function poll(id){
  try{const job=await api('/api/jobs/'+id);state.jobs=state.jobs.map(j=>j.id===id?job:j);if(job.state!=='running')state.active=null;refreshResult();if(job.state==='running')setTimeout(()=>poll(id),650);}
  catch(error){state.active=id;refreshResult();showError(T('无法获取状态；请恢复服务连接后查看记录，勿重复提交。 ','Cannot retrieve status. Restore the connection and inspect activity; do not resubmit. ')+error.message);}
}
function continueSign(id){
  const j=state.jobs.find(j=>j.id===id),m=j?.document?.manifest;if(!m)return;
  remember();state.forms.sign={module:j.fields.output||j.fields.module,policy:j.fields.policy,algorithm:'ES256','module-id':m.module_id,'module-version':m.version,'security-epoch':m.security_epoch,capabilities:m.capabilities,'not-before':stamp(Number(m.not_before)*1000),'not-after':stamp(Number(m.not_after)*1000),'allow-partial':j.state==='partial','append-signature':true};
  state.mode='append';state.page='sign';state.result=null;state.error='';state.preview='';render();window.scrollTo({top:0});toast(T('已沿用清单，请选择另一密钥、证书、CRL 与新输出路径。','Manifest retained. Choose another key, certificate, CRLs and a new output path.'));
}
let pickerTarget=null,pickerData=null;
async function openPicker(target,kind){
  pickerTarget={target,kind};const dialog=$('#picker');
  dialog.innerHTML=`<div class="picker-head"><h2 id="picker-title">${T('选择本机路径','Choose a local path')}</h2><button class="icon-button" data-action="picker-close" aria-label="${T('关闭','Close')}">${icon('close')}</button></div><div class="picker-tools"><select id="picker-root" aria-label="${T('根目录','Root directory')}">${state.config.browse_roots.map(r=>`<option>${esc(r)}</option>`).join('')}</select><button class="icon-button" data-action="picker-up" aria-label="${T('上一级','Parent directory')}">${icon('up')}</button></div><div class="picker-address"><input id="picker-address" aria-label="${T('目录路径','Directory path')}" placeholder="${T('输入目录路径','Enter a directory path')}"><button class="small-btn" data-action="picker-go">${T('前往','Go')}</button></div><div class="picker-path" id="picker-path"></div><div class="file-list" id="file-list"></div><div class="picker-bottom">${kind==='output'||kind==='directory'?`<input id="picker-filename" aria-label="${T('新名称（可选）','New name (optional)')}" placeholder="${kind==='output'?T('新文件名，例如 signed.wasm','New filename, e.g. signed.wasm'):T('新目录名，或留空选当前目录','New directory name, or blank for current directory')}"><button class="small-btn" data-action="picker-choose">${T('使用此路径','Use this path')}</button>`:`<input id="picker-filter" aria-label="${T('筛选名称','Filter names')}" placeholder="${T('筛选当前目录…','Filter this directory…')}">`}</div><div class="picker-caption">${T('也可以直接在表单输入绝对路径。','You can also enter an absolute path directly in the form.')}</div>`;
  dialog.showModal();await loadDirectory(state.config.browse_roots[0]);
}
async function loadDirectory(path){
  $('#file-list').textContent=T('正在读取目录…','Reading directory…');
  try {pickerData=await api('/api/browse',{path});$('#picker-path').textContent=pickerData.path;$('#picker-address').value=pickerData.path;$('#picker-filter')&&($('#picker-filter').value='');renderFiles();}
  catch(e){pickerData=null;$('#file-list').innerHTML=`<div class="error">${esc(e.message)}</div>`;}
}
function renderFiles(){if(!pickerData)return;const filter=$('#picker-filter')?.value.toLowerCase()||'';$('#file-list').innerHTML=pickerData.entries.filter(e=>e.name.toLowerCase().includes(filter)).map(e=>`<button class="file-row" data-action="picker-entry" data-path="${esc(e.path)}" data-kind="${e.kind}">${icon(e.kind==='directory'?'folder':'file')}<span>${esc(e.name)}</span>${e.kind==='directory'?'<small>↗</small>':''}</button>`).join('')||`<p class="picker-caption">${T('此目录下没有匹配项。','No matching entries in this directory.')}</p>`;if(pickerData.truncated)$('#file-list').insertAdjacentHTML('beforeend',`<p class="picker-caption">${T('目录条目超过 1,000 个，请直接输入更具体的路径。','Directory exceeds 1,000 entries. Type a more specific path.')}</p>`);}
function choosePath(path){const el=$('#f-'+pickerTarget.target);if(pickerTarget.kind==='paths')el.value=(el.value?el.value.trim()+'\n':'')+path;else el.value=path;$('#picker').close();remember();updateSummary();el.focus();}
function updateSummary(){const el=$('#summary-list');if(el)el.innerHTML=summaryHTML();state.preview='';if($('#command-preview'))$('#command-preview').hidden=true;}
function connectionScreen(error=''){
  document.documentElement.lang=state.lang==='zh'?'zh-CN':'en-US';
  $('#app').innerHTML=`<div class="connection-screen"><section class="connection-card"><button class="language" data-action="language-connect">${T('EN / 中','中 / EN')}</button><img src="/mark.svg" alt=""><h1>WSEA Studio</h1><p>${T('打开终端显示的会话链接，或粘贴本次启动的令牌。','Open the session link from the terminal, or paste the startup token below.')}</p><form id="connect-form"><label for="session-token">${T('本地会话令牌','Local session token')}</label><input id="session-token" type="password" autocomplete="off" required spellcheck="false"><button type="submit" class="run-btn">${T('连接本机程序','Connect to local binary')}${icon('arrow')}</button></form>${error?`<div class="error" role="alert">${esc(error)}</div>`:''}<p class="field-hint">${T('刷新页面后，请重新使用会话链接。','After refreshing, use the session link again.')}</p></section></div>`;
}
async function connect(token){state.token=token;try{state.config=await api('/api/config');state.jobs=state.config.jobs;state.active=state.config.active_job;render();if(state.active){state.result=state.active;refreshResult();poll(state.active);}}catch(e){state.config=null;connectionScreen(e.message);}}

document.addEventListener('submit',event=>{event.preventDefault();if(event.target.id==='connect-form'){connect($('#session-token').value.trim());return;}if(event.target.id==='operation-form'){remember();launch();}});
document.addEventListener('input',event=>{if(event.target.id==='picker-filter')renderFiles();else if(event.target.closest('#operation-form')){remember();updateSummary();}});
document.addEventListener('change',event=>{if(event.target.id==='picker-root')loadDirectory(event.target.value);if(event.target.id==='f-in-place'){toggleInPlace();remember();updateSummary();}});
document.addEventListener('keydown',event=>{if(event.target.id==='picker-address'&&event.key==='Enter'){event.preventDefault();loadDirectory(event.target.value);}});
document.addEventListener('click',async event=>{
  const b=event.target.closest('[data-action]');if(!b)return;const action=b.dataset.action;
  if(action==='navigate')navigate(b.dataset.page);
  else if(action==='language'||action==='language-connect'){remember();state.lang=state.lang==='zh'?'en':'zh';if(state.config)render();else connectionScreen();}
  else if(action==='mode'){remember();state.mode=b.dataset.mode;state.error='';state.preview='';render();}
  else if(action==='preview'){remember();if(!$('#operation-form').reportValidity())return;try{const preview=await api('/api/preview',{command:state.page,fields:state.forms[state.page]});state.preview=preview.display;$('#command-preview').textContent=preview.display;$('#command-preview').hidden=false;}catch(e){showError(e.message);}}
  else if(action==='browse')openPicker(b.dataset.field,b.dataset.kind);
  else if(action==='picker-close')$('#picker').close();
  else if(action==='picker-up'&&pickerData?.parent)loadDirectory(pickerData.parent);
  else if(action==='picker-go')loadDirectory($('#picker-address').value);
  else if(action==='picker-entry'){if(b.dataset.kind==='directory')loadDirectory(b.dataset.path);else if(pickerTarget.kind!=='directory')choosePath(b.dataset.path);}
  else if(action==='picker-choose'&&pickerData){const name=$('#picker-filename').value;if(pickerTarget.kind==='output'&&!name){toast(T('请填写新文件名。','Enter a new filename.'));return;}if(name==='.'||name==='..'||/[\\/\x00-\x1f]/.test(name)){toast(T('请输入一个文件或目录名称。','Enter a single file or directory name.'));return;}choosePath(pickerData.path+(name?(pickerData.path.endsWith('/')||pickerData.path.endsWith('\\')?'':pickerData.path.includes('\\')?'\\':'/')+name:''));}
  else if(action==='show-job'){state.result=b.dataset.id;refreshResult();$('#latest-result')?.scrollIntoView({block:'start',behavior:'smooth'});}
  else if(action==='continue-sign')continueSign(b.dataset.id);
  else if(action==='verify-artifact'){const j=state.jobs.find(j=>j.id===b.dataset.id);remember();state.forms.verify={module:j.fields.output||j.fields.module,policy:j.fields.policy};state.page='verify';state.result=null;state.error='';state.preview='';render();window.scrollTo({top:0});}
  else if(action==='copy-result'){const j=state.jobs.find(j=>j.id===b.dataset.id);copy(j.stdout+(j.stderr?'\n'+j.stderr:''));}
  else if(action==='version')launch('version',{});
});
const initialToken=new URLSearchParams(location.hash.slice(1)).get('token');
if(location.hash)history.replaceState(null,'',location.pathname);
if(initialToken)connect(initialToken);else connectionScreen();
