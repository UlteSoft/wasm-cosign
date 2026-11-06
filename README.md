# wasm-cosign · WSEA v2

[简体中文 · zh_CN](README.zh_CN.md) | [English · en_US](README.en_US.md)

WebAssembly 模块签名与校验，兼容 uwvm2-ros 的离线执行前授权。
Sign and verify WebAssembly modules with the WSEA v2 format used by uwvm2-ros.

- [中文完整文档](README.zh_CN.md#文档导航) · [Complete English documentation](README.en_US.md#documentation)
- [GitHub Releases](https://github.com/UlteSoft/wasm-cosign/releases)
- [CI](https://github.com/UlteSoft/wasm-cosign/actions/workflows/wsea-ci.yml) · [Release workflow](https://github.com/UlteSoft/wasm-cosign/actions/workflows/cut-release.yml)

仅 `uwvm.wsea.v2` 是当前签名容器；旧 `wasm-cosign` 容器已弃用，项目名称保持不变。
The legacy `wasm-cosign` signature container is deprecated; the project itself is active.

本仓库保留的上游 Sigstore 文档与源码不代表本产品提供 OCI、容器或任意文件签名功能。
Inherited Sigstore source and documentation do not describe the WSEA product's supported command surface.
