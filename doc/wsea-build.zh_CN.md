# WSEA 产品构建指南

[English](wsea-build.en_US.md) | [文档导航](../README.zh_CN.md)

## 产品边界与工具要求

默认原生入口为 `./cmd/cosign`，可移植入口为 `./cmd/wasmcosign`。
两者只签名／校验嵌入 WSEA v2 的 WASM。仓库保留历史 Sigstore 源码，但 OCI、容器、任意文件、
旧 `wasm-cosign` 节及无关上游命令不进入产品。不得以 `go test ./...` 替代产品测试列表。

原生发行验证使用 Go 1.26.8、C／C++20 编译器、Python 3.10+、Perl 5、make、ar、ranlib 和 pkg-config。
可移植构建固定 Go 1.26.8、WASI SDK 34.0（LLVM 23.1.0-wasi-sdk）及 Binaryen 133。
CI 另使用 LLVM 22.1.8 构建真实 UWVM 解释器，并测试 Wasmtime 42.0.1、Node.js 22.22.3。
固定下载地址与摘要记录在 `scripts/wsea_toolchains.json`。
工具版本变化需要重新验证，不能只凭一次编译成功接受。

## 工作目录与资源保护

**所有**生成文件都使用项目已忽略的 `.tmp`：构建树、本任务下载的工具链、缓存、密钥、样本、日志与报告。
工作目录及祖先目录不能由组或其他用户写入。
以下环境应在已经通过准入的本机 Linux 64 GiB、零 swap cgroup 内使用；仅设置环境变量不会建立 cgroup。

```sh
umask 077
mkdir -p .tmp/work/tmp .tmp/work/go-cache .tmp/work/go-modules
export TMPDIR="$PWD/.tmp/work/tmp" GOTMPDIR="$PWD/.tmp/work/tmp"
export GOCACHE="$PWD/.tmp/work/go-cache" GOMAXPROCS=2 WSEA_OPENSSL_JOBS=3
export GOMODCACHE="$PWD/.tmp/work/go-modules"
export PYTHONDONTWRITEBYTECODE=1
export WSEA_OPENSSL_ROOT="$PWD/.tmp/work/openssl"
```

检查真实进程成员关系、有效 `memory.max=68719476736`、`memory.swap.max=0` 及 OOM 计数。
子进程须保持在同一 cgroup，限制任务并发和超时。准入失败时不得提高宿主上限或关闭检查。
CI 在一次性 Linux systemd 单元中设置同样硬上限；macOS 原生任务运行于隔离的 GitHub 托管 runner，
不将其宣称为 Linux cgroup 测试。详见[测试指南](wsea-testing.zh_CN.md)。

## 共享校验器与固定 OpenSSL

`internal/wseanative/wsea.h` 与配套 UWVM 的 `src/uwvm2/utils/security/wsea.h` 逐字节相同，
由 `wsea.sha256` 固定。Go 生成规范 COSE 并检查模块／策略／状态。
每份签名的 COSE／PKI 验证均使用共享 C++ 实现，不回退到 Go X.509。
构建会对照 Go 表检查全部 13 种精确名称与 COSE 编号。

`third_party/openssl` 包含未修改 OpenSSL 3.5.9 源码、许可证、来源和文件清单。
`tools/dependencies/build_openssl.py` 固定为与 UWVM 相同的配方。
原生配置为 `no-shared no-tests no-apps no-module`，构建 libcrypto 和 libssl，但 cosign 只链接静态 libcrypto。
原生 HTTPS 使用 Go TLS。WASM 只构建 libcrypto，采用文档中的单线程、无 socket／动态 provider 配置，
并使用真实 WASI 熵源。

独立的 `wsea-libcrypto.pc` 指向**绝对静态库路径**，缺少捆绑库时不能静默解析成系统 `-lcrypto`。
缓存复用会验证源码、编译器、生成头文件及归档身份。
`CGO_CPPFLAGS` 携带构建记录摘要，使 Go CGO 缓存感知密码学配置变化。
这些记录是内部构建输入，不作为发行附件。

发行验证必须明确提供准确的配套源码目录。核心或密码学变更要求两个仓库同步，并重新运行完整运行时矩阵。
只有头文件相同，不能证明另一份 OpenSSL 或 ABI 已获验证。
WASM 专用宏排除 POSIX 状态／执行凭据 API，禁止在非 WASM 或原子／线程构建中启用，
不改变原生默认实现。

## 原生构建与直接 Go 命令

```sh
make cosign UWVM2_ROOT=../uwvm2-ros
make test UWVM2_ROOT=../uwvm2-ros
./cosign wasm secure --help
```

使用上述环境，将 OpenSSL 与测试临时文件留在 `.tmp`。
`make bundled-openssl` 后若需要直接运行 Go：

```sh
export PKG_CONFIG_PATH="$WSEA_OPENSSL_ROOT/pkgconfig"
export PKG_CONFIG_LIBDIR="$PKG_CONFIG_PATH" PKG_CONFIG_SYSROOT_DIR=
export CGO_CPPFLAGS="$(cat "$WSEA_OPENSSL_ROOT/cgo-cppflags")"
CGO_ENABLED=1 go build -p=2 -trimpath -o .tmp/work/cosign ./cmd/cosign
CGO_ENABLED=1 go test -p=2 ./cmd/cosign ./cmd/wasmcosign \
  ./internal/wasmcli ./internal/wasmsdk ./internal/wseanative \
  ./pkg/wasmsecure ./cmd/cosign/cli/wasmsecure
```

Linux 静态发行使用 `netgo,osusergo,wsea_static` 和外部静态链接，具体见 `scripts/build_wsea_release.py`。
原生产品设置 `CGO_ENABLED=0` 会构建失败，不会选择弱校验器。
继承的 Go 模块名称仍是 `github.com/sigstore/cosign/v3`，通过模块代理构建上游同名路径，
不等于构建本次审查的 fork，必须从本仓库检出的源码构建。

## 交叉编译与平台验证

明确提供目标 `CC`、`CXX`、`PKG_CONFIG` 和 `WSEA_OPENSSL_SPEC`。
JSON spec 使用 UWVM 的编译器／ABI 字段：`platform`、`arch`、`cc`、`ar`、`ranlib`、
`cflags`、`ldflags`，以及可选 `configure_target`／`float_abi`，必须与目标 `GOOS`／`GOARCH` 匹配。
每个目标分别使用 OpenSSL／工作目录。
`make cross WSEA_GOOS=linux WSEA_GOARCH=arm64` 只构建所选目标，不代表全平台发布。

原生发行构建器对交叉构建要求真实执行前缀，例如 `--exec-prefix-json '["/trusted/qemu-aarch64"]'`，
并执行产品测试二进制与最终 CLI。只有编译成功而未在目标执行，不能生成合格发行结论。
更广泛 QEMU 测试中的 `run_go_targets.py` 要求显式原生工具链及匹配的 UWVM 证据。

Windows／DOS 当前缺少受保护的原生 WSEA 后端。Go 没有 powerpc32 或 sparc64 移植，
CGO 不支持 Linux 大端 powerpc64。不得重命名另一平台程序或改用纯 Go 来填补缺失平台。
自动发布矩阵与原生构建器可能支持的更广目标列表分开说明。

## 构建 WASIp1 与 JavaScript

使用 `scripts/fetch_wsea_toolchains.py --output .tmp/tools` 下载并验证工具，
或自行提供完全匹配的固定官方工具。下载器在安全解压前检查归档 SHA-256，构建器自身不下载。
无需 Emscripten 或第三方预编译 OpenSSL WASM。

```sh
python3 scripts/build_wsea_wasm.py \
  --wasi-sdk .tmp/tools/wasi-sdk --wasm-opt .tmp/tools/binaryen/bin/wasm-opt \
  --uwvm-root ../uwvm2-ros --output .tmp/wsea-wasm --jobs 3
```

输出为 `wasm-cosign-wasi.wasm`、`wasm-cosign-js.wasm` 及一个共用的 `wsea-crypto.wasm`。
只编译 `wasm32-wasip1` 与 Go `js/wasm`。Binaryen 降低必要指令并严格验证 MVP，
不启用线程、SIMD、GC、memory64 或 WASIp2。
WASM 导入依赖图限制为四个产品包及 Go 标准库，运行时支持脚本必须匹配 Go 版本。

编译器、配方或密码学身份变化后不得复用旧缓存，应选择新输出目录，不能修改记录强迫通过。
提交源码后，使用 `scripts/package_wsea_wasm.py`，提供明确版本、产物目录、新输出目录及配套根目录。
它在归档前检查双方已提交头文件、源码摘要和每个所选文件。
发布前必须执行的验证门槛见 [CI/CD 指南](wsea-release.zh_CN.md)。
