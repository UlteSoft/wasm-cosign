#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors.
# Licensed under the Apache License, Version 2.0.
"""Generate bilingual release notes for the gated five-target workflow."""
import re
import sys

version = sys.argv[1]
if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', version):
    sys.exit('explicit semantic release version required')
base = 'https://github.com/UlteSoft/wasm-cosign/blob/' + version
print(f'''# wasm-cosign {version}

## 简体中文

本版本提供完整、相互对应的 zh_CN / en_US 文档，覆盖原生命令、WSEA 安全规则、
多签与版本轮换、WASIp1、浏览器 / Node SDK、构建、测试及 CI/CD。
[中文文档]({base}/README.zh_CN.md)

发行目标：Linux x86_64（静态）、macOS 15+ AArch64 / x86_64、wasm32-wasip1、wasm32-js。
其他平台旧版文件仍可在原标签下载，本次不将未运行目标测试的平台列为新版本支持。
所有包包含两种语言文档、许可证及源码身份信息，SHA256SUMS 校验归档。

发布流程在真实 UWVM、Wasmtime、Node 中验证 277 个对照用例、76 项互通签名检查和
13 项宿主安全检查，并执行原生产品测试、双方源码一致性与严格 MVP 检查。
Linux 资格验证使用 64 GiB、零 swap cgroup；macOS 在各架构托管 runner 原生测试。
测试密钥、样本、日志、结果和构建中间文件不进入附件。

WSEA v2 容器与 13 种算法不变。支持至多八个不同密钥的混合多签。
WASM 只使用 Preview 1 / MVP，无 WASIp2；UWVM 执行前校验仍离线、显式启用。
浏览器宿主必须保护可信策略及防回退快照，SDK 成功不替代 VM 的 --secure 执行授权。
本版本还固定了配套 UWVM 的解释器诊断回退编译修复，未修改 WSEA 校验规则。

## English

Complete matching zh_CN / en_US documentation now covers the native CLI, WSEA
security rules, multi-signatures and key/version rotation, WASIp1, browser / Node
SDKs, building, testing and CI/CD. [English documentation]({base}/README.en_US.md)

Targets: static Linux x86_64, macOS 15+ AArch64 / x86_64, wasm32-wasip1 and wasm32-js.
Older assets for other platforms remain at their original tags; unexecuted target
configurations are not qualified by this release. Every archive includes both
documentation languages, licenses and source provenance; SHA256SUMS covers archives.

Publication requires 277 corpus cases and 76 signing/interoperability checks on
real UWVM, Wasmtime and Node, 13 host-security checks, native product tests,
paired-source checks and strict MVP validation. Linux qualification uses a 64 GiB
zero-swap cgroup; macOS runs natively on the matching hosted architecture.
Generated keys, fixtures, logs, reports and build intermediates are excluded.

The WSEA v2 container and all 13 algorithm profiles are unchanged, including mixed
quorums of up to eight distinct keys. WASM remains Preview 1 / MVP, with no WASIp2.
UWVM's execution gate remains offline and explicit. Browser hosts must protect
trusted policy and rollback snapshots; an SDK result is not --secure VM authorization.
The paired UWVM revision also fixes compilation of its interpreter diagnostic
fallback without changing the WSEA verification rules.
''')
