// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
// Low-level SDK transport for trusted callers. For protected file workflows use
// run.py. JSON supplied by an untrusted peer is NOT a source of trust policy.
import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL, fileURLToPath} from 'node:url';
import {createWsea} from './loader.mjs';

const assets = process.argv[2] || path.dirname(fileURLToPath(import.meta.url));
await import(pathToFileURL(path.join(assets, 'wasm_exec.js')).href);
const sdk = await createWsea({
  cryptoBytes: fs.readFileSync(path.join(assets, 'wsea-crypto.wasm')),
  frontendBytes: fs.readFileSync(path.join(assets, 'wasm-cosign-js.wasm')),
  go: new globalThis.Go(), diagnostic: text => process.stderr.write(text),
});
const chunks = [];
let size = 0;
let pending = '';
const stream = process.argv[3] === '--stream';
const decoder = new TextDecoder('utf-8', {fatal: true});
for await (const chunk of process.stdin) {
  if (stream) {
    pending += decoder.decode(chunk, {stream: true});
    if (pending.length > 96 * 1024 * 1024) throw new Error('SDK request too large');
    let split;
    while ((split = pending.indexOf('\n')) !== -1) {
      process.stdout.write(sdk.requestJSON(pending.slice(0, split)) + '\n');
      pending = pending.slice(split + 1);
    }
    continue;
  }
  size += chunk.length;
  if (size > 96 * 1024 * 1024) throw new Error('SDK request too large');
  chunks.push(chunk);
}
if (stream) {
  pending += decoder.decode();
  if (pending.length) throw new Error('Incomplete request stream');
} else {
const input = Buffer.concat(chunks);
const result = sdk.requestJSON(decoder.decode(input));
input.fill(0); for (const chunk of chunks) chunk.fill(0);
process.stdout.write(result + '\n');
process.exitCode = JSON.parse(result).status === 'REJECTED' ? 1 : 0;
}
