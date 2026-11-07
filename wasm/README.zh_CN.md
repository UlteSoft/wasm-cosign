# WSEA WebAssembly SDK

[English](README.en_US.md) | [文档导航](../README.zh_CN.md)

本移植版本只签名和校验 **WebAssembly 模块**，使用既有 `uwvm.wsea.v2` 自定义节。
WSEA 载荷、COSE 算法编号、X.509／CRL 规则及多签门槛解释均保持不变。
已弃用的 `wasm-cosign` 容器和非 WASM 签名接口不包含在产品中。

两个发行包包含相同的 `wsea-crypto.wasm`，由固定 OpenSSL 3.5.9 源码和与 UWVM 共享的 WSEA 头文件编译。
Go 实现与原生 cosign 相同的签名、模块解析、受保护策略和防回退规则。
验证不会回退到 Go X.509、WebCrypto 签名验证或宿主的另一份 OpenSSL。
WebCrypto 在 JavaScript 宿主中仅提供安全随机源。

支持 `ES256`、`ESP256`、`ES384`、`ESP384`、`ES512`、`ESP512`、`Ed25519`、
`PS256`、`PS384`、`PS512`、`RS256`、`RS384`、`RS512`。
最多八份签名；门槛按不同的已授权 SPKI 计数，同一密钥重复签名只算一次。
每份现有签名均须有效，且认证同一清单。与 UWVM 一样，仅支持纯 Ed25519，拒绝 Ed25519ph 和 Ed25519ctx。

## 目标平台

- **wasm-wasi**：`wasm-cosign-wasi.wasm` 与 `wsea-crypto.wasm`，均为使用 **WASI Preview 1** 的核心 WASM 模块。
  Wasmtime 使用具名预加载，UWVM 使用模块预加载器进行链接。不构建或发布 Preview 2／组件模型产物。
- **wasm-js**：`wasm-cosign-js.wasm`、相同密码学 reactor、`wasm_exec.js` 和 `loader.mjs`。
  由 Node.js 或浏览器 JavaScript 提供宿主环境。

三个模块在降低 Go 生成的 bulk-memory、符号扩展及非陷阱转换指令后，通过严格 **MVP 指令集验证**，
也可运行于 WebAssembly 2.0 引擎。不要求 SIMD、线程、原子指令、共享内存、引用类型、GC、
异常处理、多内存或 memory64 提案。两个实例各自使用普通 wasm32 内存。
JavaScript 宿主还需支持 WebAssembly BigInt 集成、`BigInt`、`TextEncoder`／`TextDecoder`、
定时器和真正的 WebCrypto CSPRNG；这不表示支持所有 2017 年最初实现 MVP 的浏览器。

浏览器接口面向 HTTPS 安全上下文中的独立 Worker，每个 Worker 加载一个 SDK。
如果要求结束私钥生命周期，应在签名后终止 Worker；JavaScript／Go 字符串不能保证彻底擦除每个私钥副本。
应用应设置超时与内存预算。SDK 不会创建网站、供应信任或下载密钥。
可信宿主可通过 `fetch` 执行 HTTPS 下载与 TLS 校验，再以字节形式提供材料。
下载的证书不会自动成为本地信任锚。

## 受保护的本地文件

在 POSIX 上使用 `run.py`（Python 3.10+）读取操作员选择的受保护策略、信任根、防回退状态及私钥。
选择与运行时匹配的发行包，在解压目录运行：

```sh
python3 run.py --runtime wasmtime verify module.wasm --policy /protected/policy
python3 run.py --runtime uwvm --engine /trusted/uwvm2-ros verify module.wasm --policy /protected/policy
python3 run.py --runtime node verify module.wasm --policy /protected/policy
```

适配器使用文件描述符解析安全路径，拒绝符号链接、非授权拥有者、组／其他用户可写祖先目录和安全文件硬链接。
状态目录要求 0700，状态文件要求 0600，并持有与 UWVM 相同的 `.lock`。
它检查完整的受保护撤销快照，并在返回前重查策略、根、状态和最早证据到期时间。
与原生 WSEA 一致，允许 root 拥有且带 sticky 位的祖先目录。

签名使用相同受保护策略，接受与原生实现相同的 PEM PKCS#8／PKCS#1／EC 密钥。
输出必须是**新的绝对路径**，不会静默覆盖已有文件。

```sh
python3 run.py --runtime node sign unsigned.wasm \
  --policy /protected/policy --key /protected/signer.key \
  --certificate signer-chain.pem --crl fresh-crls.pem \
  --module-id vendor.module --algorithm Ed25519 --version 1 \
  --not-before "$VALID_FROM_UTC" --not-after "$VALID_UNTIL_UTC" \
  --output /protected/release.wasm
```

有效期应按实际发行设置。`--append-signature` 追加贡献，`--replace-signature` 显式替换现有容器。
多人收集签名时，仅在签名阶段使用 `--allow-partial`；不同密钥门槛未达成时结果标记为 `SIGNED_PARTIAL`。
普通校验和 UWVM 执行始终要求受保护门槛。各份签名的清单元数据，包括有效期，必须一致。

策略初始化与管理仍由原生 cosign 或管理员完成。WASM 版本不会自动重建缺失状态、推进 VM 防回退下限，
也不会签发执行凭据。与原生 `cosign wasm secure verify` 相同，本地成功校验只是检查；
UWVM 另行通过 `--secure` 在运行所选模块前授权。
UWVM 启动器只显式授予必要的 Preview 1 时钟、CSPRNG、参数／空环境、标准输入输出、
就绪等待、单调定时器及退出操作，不授予文件系统预打开、宿主环境继承或网络能力。

## 浏览器／Node 纯内存接口

可信应用必须提供**独立认证**的策略、信任根、当前受保护防回退状态及完整永久撤销列表。
这些内容不能从签名模块中建立信任，也不能由不可信 HTTP 请求自行选择。
WASI／浏览器存储本身不能认证 POSIX 拥有者。服务端必须从受保护存储获取快照；
Web 应用必须定义同等可信的供应和新鲜度机制。如果做不到，就不能报告可信部署授权。

```js
// 在独立的模块 Worker 中运行。
import './wasm_exec.js';
import {createWsea} from './loader.mjs';
const sdk = await createWsea({
  cryptoBytes: await (await fetch('./wsea-crypto.wasm')).arrayBuffer(),
  frontendBytes: await (await fetch('./wasm-cosign-js.wasm')).arrayBuffer(),
  go: new globalThis.Go(),
});
const responseJSON = sdk.requestJSON(trustedRequestJSON);
```

必须使用同一包内的 `wasm_exec.js`，不能换成其他 Go 版本。
Node 的低层传输入口为 `node run-json.mjs /absolute/package < trusted-request.json`。
直接使用 Wasmtime：

```sh
wasmtime run --preload wsea_crypto=./wsea-crypto.wasm \
  ./wasm-cosign-wasi.wasm < trusted-request.json
```

低层传输接收一个 UTF-8 JSON 对象。`--stream` 以换行分隔请求，每行返回一个响应。
流模式下预期拒绝通过 `status` 表示，不能只看进程退出状态，宿主必须检查每个响应。
默认单请求模式在拒绝时非零退出。

JSON 传输模式名为 `wsea-sdk-1`，**不是新的签名容器**。
二进制字段用标准 base64；成员名必须完全匹配、小写且区分大小写。
重复／未知字段、尾随 JSON 和非法 UTF-8 都被拒绝。校验请求：

```json
{
  "schema": "wsea-sdk-1",
  "operation": "verify",
  "module": "BASE64_WASM_BYTES",
  "trust": {
    "policy": "BASE64_PROTECTED_POLICY_BYTES",
    "roots": "BASE64_PROTECTED_ROOT_PEM",
    "state": "BASE64_CURRENT_PROTECTED_STATE_BYTES",
    "revoked_spkis": []
  }
}
```

`revoked_spkis` 为必填字段，没有撤销时也必须显式提供空列表；不能把省略解释为“假定无人被撤销”。
状态不会隐式初始化。签名请求将 `operation` 设置为 `sign`，添加 `signing`，其中包含
`key`、`certificates`、`crls`（base64 字节）、`manifest`、`append`、`replace` 和 `allow_partial`。
清单字段为 `embedded: true`、`algorithm`、`module_id`、`version`、`security_epoch`、
`not_before`、`not_after`、`abi: "uwvm2"` 和 `capabilities`。
时间使用无符号 Unix 秒；长度和摘要根据实际未签名前缀计算。

响应可以是带错误信息的 `REJECTED`、`SIGNED_PARTIAL`，或者包含认证清单 `manifest`、
`checked_at` 和排他到期边界 `valid_until` 的 `VERIFIED_SNAPSHOT`。
签名还返回 base64 模块。使用结果前，宿主必须再次检查当前受保护信任／状态、时钟回退及到期时间。
`VERIFIED_SNAPSHOT` 永远不是 UWVM 执行凭据。
运行时 trap、熵源失败、缺失导入或响应格式异常均须拒绝，不存在成功回退路径。

版本、epoch、能力位及时间戳均为 uint64 整数。应保留 JSON 原文或使用支持无损整数的 JSON 库。
普通 JavaScript `JSON.parse`／`JSON.stringify` 往返会舍入大于 2^53-1 的整数，不能用于安全计数器。
三个运行时均覆盖 uint64 最大值测试。

SDK 操作上限为：完整模块 32 MiB、JSON 传输 96 MiB、策略／COSE 64 KiB、每个 PEM 包 4 MiB、
状态 1 MiB，以及 8192 个撤销指纹。受保护策略可以更严格。
这些资源约束不会放宽原生 WSEA 接受规则；原生可处理的更大部署并不一定受浏览器 SDK 支持。
原生 CLI 的 HTTPS 功能保持不变；此可移植入口只暴露 sign／verify。

## 构建与验证

发行使用 Go 1.27.3、WASI SDK 34.0（LLVM 23.1.0-wasi-sdk）、Binaryen 133 及未修改的捆绑 OpenSSL 3.5.9。
不依赖 Emscripten 或第三方预编译 OpenSSL WASM。
OpenSSL 原有 `__wasi__` 熵源路径调用 `random_get`；没有固定种子、RAND_status 绕过或宿主密码学替换。
SDK 模拟进程 ID 仅用于 nonce 个性化，不能提供熵。
密码学 reactor 只构建和链接 `libcrypto.a`，不包含应用、libssl、engine、动态 provider、socket 或 OpenSSL 配置加载。

使用官方归档，并在解压使用前验证 SHA-256：

- [WASI SDK 34.0 x86_64 Linux](https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-34/wasi-sdk-34.0-x86_64-linux.tar.gz)：
  `b761e3a0721dbae9c09a0059e5fdb2bf917d1b4a8a7b430fb3b5aafb0984b2c4`
- [Binaryen 133 x86_64 Linux](https://github.com/WebAssembly/binaryen/releases/download/version_133/binaryen-version_133-x86_64-linux.tar.gz)：
  `2dc9c7813f5375db93d96ead4b78222fcc3e2677bbb832297af4797782a37489`

本机 Linux 构建和验证使用经过确认的 64 GiB、零 swap cgroup。
`TMPDIR`、`GOTMPDIR`、缓存、密钥和结果均放入项目已忽略的 `.tmp`。
不能因工作目录可由组写入而关闭受保护路径检查。

```sh
python3 scripts/build_wsea_wasm.py --wasi-sdk /trusted/wasi-sdk-34.0 \
  --wasm-opt /trusted/binaryen-version_133/bin/wasm-opt \
  --uwvm-root ../uwvm2-ros --output .tmp/wsea-wasm
```

构建器检查共享校验器、已定型算法编号、源码清单、编译器身份、OpenSSL 归档／生成头文件缓存摘要、
WASM 生产依赖范围和 MVP 验证。新工具链版本必须重新验证，不能仅因编译成功就自动接受。

使用 UWVM 的 `algorithm_matrix.py` 以及真实 OpenSSL Ed25519ph／ctx 生成器创建样本。
通过 `test/wsea/wasm_interop.py` 和 `test/wsea/wasm_signing.py --help` 查看必要参数。
前者保持分组策略／防回退／撤销历史，对照原生 UWVM 和 WASM 运行时执行全部 277 个用例。
后者在三个运行时使用全部 13 种类型签名，并检查原生 cosign／UWVM 接受、八密钥混合门槛、
部分签名／重复密钥拒绝、轮换、回退、全宽整数及实际安全 VM 执行。
源码测试还检查原生／快照状态一致性和歧义 JSON 拒绝。

发行包只包含指定 WASM 模块、宿主适配器、完整双语产品文档、许可证和归档校验和。
工具链、私钥、样本、日志、测试报告和构建记录均排除。
提交审查后的源码，再运行 `scripts/package_wsea_wasm.py`，提供
`--artifacts .tmp/wsea-wasm/artifacts --output .tmp/release-assets`、明确的 `--version` 及 `--uwvm-root`。
脚本对照构建记录检查源码／产物摘要，按精确文件白名单打包。
`RELEASE.json` 记录两个已提交校验器版本及生产文件摘要，不包含测试输入或结果。

## 集成生命周期与故障排查

从应用自己经过身份验证的源提供包内 JavaScript 和 WASM；读取下载字节前检查 HTTP 状态。
WASM 响应使用 `application/wasm`，`.mjs` 使用 JavaScript MIME 类型。
示例使用 `arrayBuffer`，不依赖流式编译的 MIME 条件。
CSP 应允许自己的 Worker 和 WebAssembly 编译，不加载不可信第三方脚本。
这些单线程模块不引入 SharedArrayBuffer 或跨源隔离要求。

每个独立 Worker 只初始化一次 SDK，串行处理请求。发生 trap 或超时后终止 Worker，不复用已陷入异常的 reactor。
两个 WASM 实例内存独立；加载器只复制有界值，不把一个实例的指针交给另一个。
空响应、异常格式或未知状态都视为拒绝。宿主应用不得记录含私钥的请求。

浏览器缓存或 IndexedDB 记录不是独立可信的防回退存储。
如果攻击者能选择根、策略、状态或 JavaScript，密码学运算正确也无法证明预期发布者身份。
上线 Web 界面前必须设计供应、新鲜度与失陷恢复流程。
TLS 能认证选定服务器，但不会让任意服务器提供的密钥自动获得本地 WSEA 策略授权。

导入无法解析时，使用同一发行包内的匹配文件和受支持运行时，不要添加宽泛文件／网络导入。
随机源不可用时应恢复真实 CSPRNG，不能替换成确定性种子。
输入超过资源上限时拒绝或选择另行验证的原生部署；修改上限需审查并重新测试。

[原生命令指南](../doc/wsea-cli.zh_CN.md)说明初始化与轮换，
[CI/CD 指南](../doc/wsea-release.zh_CN.md)说明自动构建和发布。
此实现不需要 Emscripten 运行时或下载第三方 OpenSSL WASM 二进制。
