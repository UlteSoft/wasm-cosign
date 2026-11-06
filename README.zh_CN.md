# wasm-cosign：使用 WSEA v2 为 WebAssembly 签名

简体中文 | [English](README.en_US.md)

wasm-cosign 的签名与校验对象**只有 WebAssembly 模块**。原生命令、WASIp1 SDK
和 JavaScript SDK 均使用 uwvm2-ros 接受的已定型签名容器 `uwvm.wsea.v2`。
HTTPS 下载、TLS 身份验证、证书链、CRL 和受保护的本地策略管理，都是为 WASM 签名服务的辅助功能。

名为 `wasm-cosign` 的旧自定义节签名容器已经 **deprecated（弃用）**。
弃用的是旧容器，不是项目名称。仅修改自定义节名称不能转换签名。
新签名必须使用 `cosign wasm secure` 或 WSEA SDK。
OCI／容器签名、任意文件签名以及上游 keyless 命令均不进入生产构建依赖图。

## 文档导航

以下指南均维护内容完整、相互对应的 `zh_CN` 和 `en_US` 版本。
不带语言后缀的文档只作导航入口，不形成第三套文档。

1. [安全模型与互操作规则](doc/wasm-secure-execution.zh_CN.md)：精确算法类型、信任边界、多签、撤销和防回退。
2. [原生命令与部署指南](doc/wsea-cli.zh_CN.md)：初始化、签名、校验、HTTPS 获取、密钥轮换和执行器授权。
3. [WASIp1 与 JavaScript SDK](wasm/README.zh_CN.md)：受保护文件适配器、Worker 集成、JSON 协议、整数精度和资源限制。
4. [构建与依赖要求](doc/wsea-build.zh_CN.md)：固定 OpenSSL、配套 UWVM 提交、原生／交叉编译和 WASM 构建。
5. [测试与发行验证](doc/wsea-testing.zh_CN.md)：本机 64 GiB cgroup、运行时矩阵、拒绝用例和发行证据。
6. [CI/CD 与发布维护](doc/wsea-release.zh_CN.md)：PR 检查、标签发布、打包白名单、校验和、重试与维护。

## 选择发行包

从 [GitHub Releases](https://github.com/UlteSoft/wasm-cosign/releases)
下载压缩包及 `SHA256SUMS`。按实际宿主系统和 CPU 架构选择；某一版本未提供的平台，
不能视为该版本已验证的平台。旧版本的发行文件仍保留在各自标签下。

- **原生 `cosign`**：面向受支持 POSIX 平台的操作员命令行，提供策略管理和经过 TLS 验证的 HTTPS 模块下载。
- **`wasm32-wasip1`**：两个核心 WASM 模块，通过 Wasmtime 或兼容的 UWVM 预加载器运行。
  仅使用 WASI Preview 1，不生成 Preview 2。
- **`wasm32-js`**：Go 前端、相同的密码学 reactor、Go 支持脚本和 ES 模块加载器，
  可用于 Node.js 或浏览器 Worker。浏览器应用必须自行建立可信策略／状态供应机制并提供安全随机源。

WASM 模块通过 MVP 指令集验证，也可运行于 WebAssembly 2.0 引擎。
JavaScript 宿主还需要 BigInt 集成及现代 Web API；字节码兼容 MVP 不代表所有早期浏览器都受支持。

下载后先验证压缩包，再解压：

```sh
sha256sum -c SHA256SUMS
# macOS：shasum -a 256 -c SHA256SUMS
```

与压缩包来自同一发行页的校验和能够发现下载损坏或文件混淆，但不等同于独立的发布者签名。
WASM 包内的 `RELEASE.json` 记录源码提交、共享校验器提交和所打包文件的摘要。
实际提供的平台及完成的验证范围，以该版本发行说明为准。

## 首次部署

先准备由管理员控制的私有目录，包含独立建立信任的 CA、签名证书、受保护的签名私钥及新鲜完整 CRL。
生产环境不得信任测试生成的密钥。按[命令指南](doc/wsea-cli.zh_CN.md)完成策略和状态初始化后再签名。

```sh
./cosign version
./cosign wasm secure --help
./cosign wasm secure verify release.wasm --policy /protected/policy
uwvm2-ros --secure module /absolute/release.wasm /protected/policy \
  --run /absolute/release.wasm
```

cosign 校验是部署阶段的检查，不会授权未来某次 VM 执行。
UWVM 的第二道检查需要通过 `--secure` 为每个模块显式选择；内置校验器保持离线，
并在接近执行的位置重新检查。不带该选择的普通执行不表示进行过签名校验。

## 安全约定

支持全部 13 种精确类型：`ES256`、`ESP256`、`ES384`、`ESP384`、`ES512`、
`ESP512`、`Ed25519`、`PS256`、`PS384`、`PS512`、`RS256`、`RS384`、`RS512`。
一个容器可携带 1 至 8 份签名。所有现有签名都必须有效，策略门槛按不同的已授权公钥计数。
仅支持纯 Ed25519，不支持 Ed25519ph／ctx 或 Ed448。

构建期间会检查共享 UWVM 校验器头文件、固定 OpenSSL 源码及算法编号的一致性。
源码相同不能替代实际目标平台测试。浏览器及 WASI 的纯内存接口验证的是宿主提供的快照；
可信存储、撤销列表完整性和时钟新鲜度仍由宿主负责。嵌入 API 前请阅读安全和 SDK 指南。

## 开发与贡献

所需工具及准确构建命令见[构建指南](doc/wsea-build.zh_CN.md)。使用产品测试入口，
不要以会编译上游无关源码的 `go test ./...` 代替产品验证。
生成的密钥、样本、日志、编译缓存和临时输出统一存放在项目已忽略的 `.tmp` 中。
本机 Linux 构建和测试使用已授权的 64 GiB、禁用 swap 的 cgroup。
不得为了适应可写的工作目录而放宽受保护路径检查。

修改行为时同时更新两种语言文档，补充有意义的回归测试，并保持已定型 WSEA 格式。
运行 `python3 scripts/check_wsea_docs.py` 检查文档配对与本地链接。
不得在公开 issue 中提交私有签名材料。项目与捆绑组件分别遵循各自许可证，见 `LICENSE` 和包内许可证。
