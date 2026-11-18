// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
// Check that the host exposes the frontend's validators and fails closed if the
// frontend returns an invalid exchange. The runtime matrix tests real WASM.
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {createWsea} from '../../wasm/loader.mjs';

if (!globalThis.crypto) globalThis.crypto = webcrypto;
const compile = WebAssembly.compile;
const instantiate = WebAssembly.instantiate;
const imports = WebAssembly.Module.imports;
const coreModule = {};
const seen = [];
let corrupt = false;
try {
  WebAssembly.compile = async () => coreModule;
  WebAssembly.Module.imports = () => [];
  WebAssembly.instantiate = async module => module === coreModule
    ? {exports: {memory: new WebAssembly.Memory({initial: 1})}}
    : {instance: {}};
  const go = {importObject: {}, exited: false, run() {
    globalThis.wseaRequestJSON = () => corrupt ? 'corrupt' : 'response';
    globalThis.wseaValidateRequestJSON = text => (seen.push(['request', text]), text === 'request');
    globalThis.wseaValidateResponseJSON = text => (seen.push(['response', text]), text === 'response');
    globalThis.wseaValidateExchangeJSON = (request, response) =>
      (seen.push(['exchange', request, response]), request === 'request' && response === 'response');
    globalThis.wseaValidateExchangeEnvelopeJSON = text => text === 'envelope';
    return new Promise(() => {});
  }};
  const sdk = await createWsea({cryptoBytes: new Uint8Array(), frontendBytes: new Uint8Array(), go});
  assert.equal(sdk.validateRequestJSON('request'), true);
  assert.equal(sdk.validateRequestJSON('invalid'), false);
  assert.equal(sdk.validateRequestJSON(null), false);
  assert.equal(sdk.validateResponseJSON('response'), true);
  assert.equal(sdk.validateExchangeJSON('request', 'response'), true);
  assert.equal(sdk.validateExchangeEnvelopeJSON('envelope'), true);
  assert.equal(sdk.requestJSON('request'), 'response');
  assert.deepEqual(seen.at(-1), ['exchange', 'request', 'response']);
  corrupt = true;
  assert.throws(() => sdk.requestJSON('request'), /invalid response/);
  assert.throws(() => sdk.validateRequestJSON('request'), /invalid response/);
} finally {
  WebAssembly.compile = compile;
  WebAssembly.instantiate = instantiate;
  WebAssembly.Module.imports = imports;
}
console.log('PASS: SDK validator routing and fatal response handling');
