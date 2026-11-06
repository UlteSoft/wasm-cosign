# CI/CD 与发布维护

[English](wsea-release.en_US.md) | [文档导航](../README.zh_CN.md)

## 版本与兼容性

发行仓库为 [UlteSoft/wasm-cosign](https://github.com/UlteSoft/wasm-cosign/releases)。
发行标签采用明确的 `vMAJOR.MINOR.PATCH`，位于已审查的 `main` 历史中。
标签和已经公开的附件保持不可变，修正使用新的 patch 版本。
WSEA 线格式独立固定为 `uwvm.wsea.v2`，工具版本变化并不允许改变格式、算法编号或安全语义。
`wsea-sdk-1` 是内存传输名称，不是另一种签名容器。旧 `wasm-cosign` 容器继续保持弃用。

v0.2.1 增加完整双语产品文档、自动可移植／原生验证和带检查门槛的 GitHub 发布。
每个新发行包同时携带两种语言。此前原生和可移植版本的文件保持原样。
配套 UWVM 提交包含解释器配置的诊断回退编译小修复，不改变共享校验器。
准确配套提交记录在 `scripts/wsea_uwvm_revision.txt`，不使用浮动分支名。

## 持续集成

向 `main` 推送及创建 PR 时运行检查，仓库 token 只读，checkout 不保留凭据。
WSEA 工作流使用的外部 action 全部固定完整提交 SHA。工具链归档固定地址及 SHA-256，新版本需要明确源码修改和重新验证。

- **Bilingual documentation**：检查语言配对、章节／示例数量、本地链接及锚点，拒绝跟踪 `.tmp` 资料。
- **CI-Tests**：在 Linux 与 macOS 执行原生产品测试，另有 Linux race 测试、捆绑 OpenSSL 检查和生成 CLI 帮助对照。
- **WSEA CI**：构建共享密码学 reactor 和两个前端，验证 MVP，构建固定提交的真实 UWVM 解释器，
  执行完整矩阵、签名与宿主安全套件；源码检查对照两个仓库。
- 产品 linter 和空白检查独立保留。历史上游容器／conformance 任务不能成为 WSEA 发行证据。

生成文件留在 `.tmp`。Linux 构建／测试任务使用一次性 systemd 单元，硬内存上限 64 GiB、
swap 为零、限制 CPU／进程数并设置任务超时；内存压力时还有更低的软限制用于节流。
可移植验证检查真实叶节点及 OOM 计数。macOS 使用独立原生托管 runner。
不存在更换密码学或跳过失败测试的回退。

## 自动发行目标

自动发布从同一不可变源码标签构建十五个归档：

- 静态 GNU/Linux：`aarch64-linux-gnu`、`armv7-linux-gnueabihf`、`i686-linux-gnu`、
  `loongarch64-linux-gnu`、`mips64-linux-gnu`、`mips64el-linux-gnu`、
  `powerpc64le-linux-gnu`、`riscv64-linux-gnu`、`x86_64-linux-gnu`。
- 静态 musl Linux：`x86_64-linux-musl`。
- 原生 FreeBSD：`x86_64-freebsd15`，要求 FreeBSD 15.1 或更新版本。
- 原生 macOS：`aarch64-apple-darwin`、`x86_64-apple-darwin`，要求 macOS 15+。
- 可移植 SDK：`wasm32-wasip1`、`wasm32-js`，使用同一密码学 reactor，严格限制为 MVP。
  不提供 WASIp2 构建。

i686 要求 SSE2；ARMv7 使用 hard-float ABI；PowerPC64 LE 要求 POWER8 或更新处理器；
MIPS64 使用 n64 硬件浮点 ABI。macOS 与 FreeBSD 静态链接内置 OpenSSL，同时使用系统 C/C++ 库。

`wsea-cross-assets.yml` 使用实际 QEMU 10.2+ 执行九种 Linux 配置，并在一次性 QEMU 客体中
构建、测试 FreeBSD。FreeBSD 虚拟机使用 4 GiB 内存、两个 CPU，继承宿主的 64 GiB、零 swap
cgroup。官方 15.1 镜像与 Go 1.26.8 归档均固定 SHA-256，客体依赖仅安装到一次性磁盘叠加层。
客体构建使用普通用户，SSH 仅绑定宿主回环地址；不需要持久虚拟机或持久自托管 runner。

Linux 编译器和 sysroot 软件包的 SHA-256 固定在 `scripts/wsea_cross_toolchains.json`。
Debian／Ubuntu 软件包只解压到私有目录，不安装到宿主系统。musl SDK 保留不安全宿主路径检查；
通过在私有目录复制相同的 Go 工具链，避免使用宿主 `/usr` 下的包含路径。
共享 OpenSSL 的汇编与算法配置保持不变。每个目标必须先执行完整产品测试，覆盖签名、证书准入、
混合密钥多签、受保护状态和命令行边界，才能创建归档；解包后的可执行文件还会通过实际目标运行器检查。
不以 Windows、DOS 或其他未验证 ABI 的文件冒充受支持平台。

## 发布新标签

审查两种语言文档及固定 UWVM 配套版本，再在已授权 cgroup 内运行本机检查。
只提交生产源码、文档及测试源码。创建标签前确认未暂存生成密钥、样本、含日期验证目录、日志或结果。

```sh
git diff --check
python3 scripts/check_wsea_docs.py
git status --short
# 提交且检查成功后：
git push origin main
git tag -a v0.2.1 -m 'wasm-cosign v0.2.1'
git push origin v0.2.1
```

实际使用下一个未占用版本，不能重复使用示例标签。
推送标签启动 **WSEA release**（`cut-release.yml`），准入要求语义版本标签位于 `main` 历史中。
工作流调用原生单元／race 与生成帮助检查、双语／工作流检查、三个原生目标构建器、十个 QEMU 目标和可移植验证流程。
可移植发行测试执行的是已打包归档解压后的准确字节，而不仅是更早构建目录的文件。

全部必要任务成功后，隔离的发布任务才获得 `contents: write`。
它下载本次运行的生产归档，检查完整十五目标集合、每个文件白名单／摘要、源码／配套提交及双语文档，
生成 `SHA256SUMS`，然后创建草稿、上传已验证文件并公开发行。
持有写 token 的发布任务不执行附件二进制，也不会覆盖已有发行版。
无需额外云凭据、OIDC 签名服务或容器仓库。

## 补齐已有发行版

明确获准补充平台时，必须使用现有标签对应的原始产品提交及其固定的 UWVM 提交。
不得移动标签，也不能从较新分支构建后冒用旧版本号。可以从当前工作流分支手动触发 QEMU 工作流，
将较旧版本传入 `version`：流程会单独检出该产品标签，将待发布源码与当前构建调度脚本分开。

逐个验证缺少的目标，保留原有可执行文件归档；合并全部十五个目标后，使用 `validate_wsea_release.py`
校验，并通过 `--source-root` 指向干净的原始源码检出目录。只追加缺少的归档；确认原有归档摘要不变后，
更新汇总的 `SHA256SUMS` 和中英文发行说明，再下载最终附件进行复核。
这种补充只更新附件和发行说明，不修改不可变标签内的源码文档及历史工作流；后续标签使用当前分支
扩展后的完整矩阵。不得发布测试失败或没有实际执行过的目标。

## 归档约定与来源

原生包包含程序、命令文档、完整双语指南、许可证及 `RELEASE.json`。
可移植包只包含所选 WASM 前端、共用 reactor、必要宿主脚本、相同双语指南、许可证及 `RELEASE.json`。
打包使用源码维护的明确白名单，不递归扫入整个工作目录；文件权限、拥有者字段和时间戳会规范化。
日志、测试私钥、样本、结果、工具链和私有构建记录均不是归档成员，也不会作为 CI artifact 上传。

`RELEASE.json` 绑定发行版本、目标、产品提交、配套 UWVM 提交、WSEA 容器、OpenSSL 版本及每个生产文件摘要。
可移植元数据还记录严格 MVP 和密码学源码摘要。
`SHA256SUMS` 覆盖压缩归档。这些摘要与来源记录是完整性信息，不等同于独立的密码学发行证明。
流程不会使用只支持 WASM 的产品去签署非 WASM 归档。

## 失败恢复与仓库设置

可在**已有标签**上手动 dispatch 发布工作流来重试基础设施失败，无需移动标签。
目标缺失或测试失败都会阻止发布。代码错误应通过新的已审查提交和新标签修正。
不得使用 `continue-on-error`、降低工具版本约束或手动上传绕过目标测试的文件。

若创建草稿后失败，先检查该草稿和运行记录。工作流有意拒绝任何已存在的 release。
确认身份后，只能移除已知、尚未公开的失败草稿，再对同一标签重试；
不能为了重试删除或替换已经公开的版本。

必须启用 GitHub Actions，并允许发布任务获得 `contents: write`；维护者还需推送标签权限。
首次成功运行后可按实际任务名配置分支必需检查。
仓库规则属于管理员设置，YAML 本身不会授予这些规则。
PR 不进入发布路径，工作流不需要长期运行的 self-hosted runner。

## 文档与依赖维护

`.en_US.md` 和 `.zh_CN.md` 同时更新，不带语言后缀的文件只作语言导航。
`scripts/wsea_documents.py` 是打包与检查白名单。自动生成英文 CLI 帮助是参数拼写的机械参考，
两种完整说明文档解释相同的行为。发布前运行文档及生成帮助检查。

升级 OpenSSL 或 WSEA 头文件时，须同步提交两个仓库、更新固定摘要并重新完成相关原生／可移植验证。
修改编译器、运行时或 action 时，应审查官方发行与摘要、更新明确固定版本并测试真实产物。
CI 成功只代表所声明的覆盖，不能宣称已经证明不存在任何可能的安全缺陷。
