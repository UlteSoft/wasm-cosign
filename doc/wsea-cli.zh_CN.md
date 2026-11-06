# 原生命令与部署指南

[English](wsea-cli.en_US.md) | [文档导航](../README.zh_CN.md)

## 前提与受保护路径

使用通过发行验证的原生 `cosign`。支持的顶层命令是 `wasm secure` 和 `version`，
实际命令面可通过 `cosign --help` 查看。以下示例假定管理员已准备 0700 的 `/protected`，
其中有独立建立信任的 `roots.pem`、代码签名叶证书／中间证书 PEM、完整新鲜 CRL，以及仅拥有者可读的私钥。
路径与模块身份应替换为实际部署值。生产信任不得使用测试 CA 私钥，也不得不加判断地照搬示例身份。

策略与密钥必须使用受保护的绝对路径，祖先目录不能由其他用户写入。
不得通过 `chmod 777` 或以 root 运行不可信工作目录来绕过限制。
状态目录和文件还有额外的拥有者／权限要求，见[安全指南](wasm-secure-execution.zh_CN.md)。

## 首次初始化策略

```sh
./cosign wasm secure policy-init \
  --output /protected/policy --state-dir /protected/state \
  --trust-root /protected/roots.pem --certificate /protected/signer-chain.pem \
  --module-id vendor.module --algorithms ES256,Ed25519,PS256 \
  --minimum-version 1 --minimum-epoch 0 --capabilities 0 \
  --policy-version 1 --max-module-bytes 33554432 --max-crl-age-seconds 86400
```

`policy-init` 是管理员引导操作，不是每次校验都应执行的步骤。
它创建本地信任策略及 VM 初始防回退状态；不能通过重新初始化来消除回退拒绝。
`--certificate` 授权叶证书公钥的 SHA-256 SPKI 指纹，`--trust-root` 选择独立受信任 CA 集合。
证书名称相同本身不构成授权。

`--algorithms` 使用精确、不重复的逗号分隔白名单，默认 `ES256`。
`--minimum-version` 默认 1，`--minimum-epoch` 和 `--capabilities` 默认 0，`--policy-version` 默认 1。
默认模块上限 100 MiB，CRL 最长年龄 86400 秒。可移植 SDK 的模块上限更严格，为 32 MiB，
因此示例采用两端均适用的限制。能力掩码只能使用已知六个位（0..63），只授权访客实际所需能力。

多签场景增加 `--additional-certificate /protected/second.pem`（可重复，共至多八个不同密钥）
及 `--signature-threshold 2`。门槛默认 1，不能大于已授权的不同密钥数量。

## 为版本签名

按实际发行安排设置 RFC3339 UTC 有效期。下方变量是占位符，不是可直接照抄的固定日期。

```sh
./cosign wasm secure sign unsigned.wasm \
  --policy /protected/policy --key /protected/signer.key \
  --certificate /protected/signer-chain.pem --crl /protected/complete-crls.pem \
  --module-id vendor.module --module-version 1 --security-epoch 0 \
  --algorithm ES256 --capabilities 0 \
  --not-before "$VALID_FROM_UTC" --not-after "$VALID_UNTIL_UTC" \
  --output /protected/release.wasm
```

原生 CLI 接受所选算法支持的受保护 PEM PKCS#8、PKCS#1 或 EC 私钥。
证书包顺序为叶证书后接中间证书；CRL 包必须覆盖每个非根证书的签发者。
密钥、证书与策略授权的签名者必须匹配，私钥不会嵌入输出。
认证长度和 SHA-256 摘要由实际 WASM 前缀计算，不能由调用者随意提供。

`--output` 创建新文件并拒绝覆盖现有目标。不指定时，原生 CLI 会原子替换输入文件；
需要保留未签名输入时应明确指定 `--output`。
已有嵌入签名时必须显式使用 `--append-signature` 或 `--replace-signature`。
SDK 文件适配器始终要求新的绝对输出路径。

## 收集多签门槛

收集签名前先初始化预期签名者集合与门槛。第一份签名使用上述相同参数，加上
`--allow-partial` 并输出 `partial-1.wasm`。下一位签名者以此文件为输入，换用其密钥、证书和 CRL，
添加 `--append-signature`，保持模块身份、版本、epoch、有效期和能力位完全相同。
下一位可以使用另一种被允许的算法。每一步使用新的输出文件。
仅在尚需收集更多签名时保留 `--allow-partial`，最终签名应满足受保护门槛。

未完成门槛时明确报告 `SIGNED_PARTIAL`，不能部署。
`verify`、`fetch` 与 UWVM 均强制满足门槛，任何现有无效签名都会导致拒绝。
同一密钥即使使用另一张证书或算法名称也只算一票。既有容器至多接受八份贡献。
详见[多签规则](wasm-secure-execution.zh_CN.md#多签名与同厂商版本)。

## 校验、获取与执行

```sh
./cosign wasm secure verify /protected/release.wasm --policy /protected/policy
./cosign wasm secure fetch /protected/downloaded.wasm \
  --policy /protected/policy --url https://publisher.example/release.wasm
uwvm2-ros --secure module /protected/release.wasm /protected/policy \
  --run /protected/release.wasm
```

`verify` 读取当前状态，不推进 VM 的防回退下限。
`fetch` 验证 TLS、限制 HTTPS 响应，并在原子发布前验证完整 WSEA 模块。
传输 TLS 信任与 WSEA 本地厂商信任是两个不同用途的信任关系。
下载的证书或策略不会因 HTTPS 成功而自动成为可信来源。
UWVM 内置校验器不联网，所有必要证据必须事先可用。

`--secure module <path> <policy>` 按路径选择模块。
UWVM 也支持 `--secure named-module <path> <policy> <expected-id>` 按显式模块身份选择。
每个需要授权的模块均须配置，不能认为入口模块已签名就自动授权导入模块。
VM 独立校验所选模块，并在接近初始化的位置重新检查私有凭据。
不能在更改文件内容或信任状态后沿用之前 cosign 的成功结论执行。

## 更新策略与轮换密钥

`policy-update` 使用与 `policy-init` 相同的管理员信任／规则选项，但 `--policy-version` 必须严格递增。
保留原状态目录以及已学习的防回退／撤销历史。
应先通过策略授权新密钥，再发布由其签名的新版本，并明确过渡期采用单签还是多密钥门槛。

对每个模块维护递增发行版本及预期安全 epoch，策略最低要求与已记录下限共同生效。
旧厂商证书或相同组织名不能绕过两者。从可信来源刷新到期 CRL 和证书。
替换成旧 CRL 或删除标记都不能合法清除永久认证撤销。

## 诊断与自动化

按进程退出状态判断成功，不要匹配看似成功的输出片段。
信号、超时、后端不可用或熵源缺失都应视为失败。`SIG_005` 可能表示不支持的算法或后端，
应结合完整消息判断。`CERT_` 错误需检查链、授权、有效期和 CRL；
`POL_` 错误需检查受保护策略／状态与时钟。
不得通过降低门槛或重置下限压制错误。

自动生成的命令帮助保留英文，并由机械检查保证参数拼写与实现一致：
[secure](wsea-cli/cosign_wasm_secure.md)、[policy-init](wsea-cli/cosign_wasm_secure_policy-init.md)、
[policy-update](wsea-cli/cosign_wasm_secure_policy-update.md)、[sign](wsea-cli/cosign_wasm_secure_sign.md)、
[verify](wsea-cli/cosign_wasm_secure_verify.md)、[fetch](wsea-cli/cosign_wasm_secure_fetch.md)。
上面的双语指南完整解释相同的受支持操作；命令参数本身不翻译。
