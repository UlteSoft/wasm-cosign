// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
// Browser/Node adapter for the identical WASIp1 crypto reactor. No filesystem,
// network, process environment, dynamic code loading or host crypto verifier.
export async function createWsea({cryptoBytes, frontendBytes, go, diagnostic = () => {}}) {
  if (!globalThis.crypto?.getRandomValues) throw new Error("A cryptographically secure host random source is required");
  let core;
  const memory = () => new DataView(core.exports.memory.buffer);
  function bounds(ptr, size) {
    ptr >>>= 0; size >>>= 0;
    if (ptr > core.exports.memory.buffer.byteLength || size > core.exports.memory.buffer.byteLength - ptr) {
      throw new Error("WSEA reactor memory bounds");
    }
    return new Uint8Array(core.exports.memory.buffer, ptr, size);
  }
  const badfd = () => 8;
  const wasi = {
    environ_get: () => 0,
    environ_sizes_get: (count, bytes) => {
      bounds(count, 4); bounds(bytes, 4);
      memory().setUint32(count, 0, true); memory().setUint32(bytes, 0, true); return 0;
    },
    random_get: (ptr, len) => {
      const buffer = bounds(ptr, len);
      for (let i = 0; i < buffer.length; i += 65536) crypto.getRandomValues(buffer.subarray(i, i + 65536));
      return 0;
    },
    clock_time_get: (clock, _precision, ptr) => {
      bounds(ptr, 8);
      let nanos;
      if (clock === 0) nanos = BigInt(Date.now()) * 1000000n;
      else if (clock === 1 && globalThis.performance) nanos = BigInt(Math.floor(performance.now() * 1000000));
      else return 28;
      memory().setBigUint64(ptr, nanos, true); return 0;
    },
    fd_close: badfd, fd_fdstat_get: badfd, fd_prestat_get: badfd,
    fd_prestat_dir_name: badfd, fd_readdir: badfd, fd_seek: badfd,
    path_filestat_get: () => 76, path_open: () => 76,
    fd_write: (fd, iovs, count, written) => {
      if (fd !== 2 || count > 64) return 8;
      bounds(iovs, count * 8); bounds(written, 4);
      let n = 0;
      for (let i = 0; i < count; i++) {
        const p = memory().getUint32(iovs + i * 8, true);
        const len = memory().getUint32(iovs + i * 8 + 4, true);
        if (len > 65536 || n + len > 65536) return 28;
        diagnostic(new TextDecoder().decode(bounds(p, len))); n += len;
      }
      memory().setUint32(written, n, true); return 0;
    },
    proc_exit: code => { throw new Error(`WSEA reactor exited: ${code}`); },
  };
  const coreModule = await WebAssembly.compile(cryptoBytes);
  for (const item of WebAssembly.Module.imports(coreModule)) {
    if (item.module !== "wasi_snapshot_preview1" || !Object.hasOwn(wasi, item.name) || item.kind !== "function") {
      throw new Error(`Unexpected crypto import ${item.module}.${item.name}`);
    }
  }
  core = await WebAssembly.instantiate(coreModule, {wasi_snapshot_preview1: wasi});
  go.importObject.wsea_crypto = core.exports;
  const frontend = await WebAssembly.instantiate(frontendBytes, go.importObject);
  if (Object.hasOwn(globalThis, "wseaRequestJSON")) throw new Error("Use a separate worker for each WSEA instance");
  let fatal;
  const running = go.run(frontend.instance).catch(e => { fatal = e; });
  // Go registers synchronously before blocking in main. Never substitute a host
  // result when WASM failed to start or trapped.
  if (fatal) throw fatal;
  const request = globalThis.wseaRequestJSON;
  if (typeof request !== "function") throw new Error("WSEA frontend did not initialize");
  return Object.freeze({
    requestJSON(text) {
      if (fatal) throw fatal;
      if (go.exited) throw new Error("WSEA frontend has exited");
      if (typeof text !== "string" || text.length > 96 * 1024 * 1024) throw new Error("Bounded JSON text required");
      try {
        const result = request(text);
        if (go.exited || typeof result !== 'string') throw new Error("WSEA frontend failed without a response");
        return result;
      } catch (error) {
        fatal = error instanceof Error ? error : new Error(String(error));
        throw fatal;
      }
    },
    running,
  });
}
