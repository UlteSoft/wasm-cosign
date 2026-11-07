#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors.
# Licensed under the Apache License, Version 2.0.
"""Generate bilingual release notes for the gated complete-platform workflow."""
import re
import sys

version = sys.argv[1]
if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', version):
    sys.exit('explicit semantic release version required')
base = 'https://github.com/UlteSoft/wasm-cosign/blob/' + version
upstream = '92514f9fedfabaf562f4946469a29b18c1ea68e7'
print(f'''# wasm-cosign {version}

## 简体中文

本版本同步 [官方 cosign 上游](https://github.com/sigstore/cosign/commit/{upstream}) 的 24 个提交，
发行工具链更新为 Go 1.27.3。新增独立的本地 Python Web GUI，提供中英文签名、校验、多签、
策略管理和 HTTPS 获取，文件由系统对话框选择，网页仅接收必要的 JSON 结果。

完整、相互对应的 zh_CN / en_US 文档覆盖原生命令、WSEA 安全规则、
多签与版本轮换、WASIp1、浏览器 / Node SDK、构建、测试及 CI/CD。
[中文文档]({base}/README.zh_CN.md)

发行目标共 15 个：静态 Linux AArch64、ARMv7 hard-float、i686、LoongArch64、
MIPS64 大端 / 小端、PowerPC64 LE、RISC-V64、x86_64 GNU / musl；
FreeBSD 15.1+ x86_64、macOS 15+ AArch64 / x86_64、wasm32-wasip1、wasm32-js。
另提供独立 `webgui` 压缩包：需要已有本机二进制及 Python 3.10+ / Zenity 或 Tk，不会自动编译。
所有包包含两种语言文档、许可证及源码身份信息，SHA256SUMS 校验全部 16 个归档。

发布流程在真实 UWVM、Wasmtime、Node 中验证 277 个对照用例、76 项互通签名检查和
13 项宿主安全检查，并执行原生产品测试、双方源码一致性与严格 MVP 检查。
Linux 与 FreeBSD/QEMU 资格验证使用 64 GiB、零 swap cgroup；macOS 在各架构托管 runner 原生测试。
所有新增原生目标都执行完整产品测试；Linux 交叉目标使用实际 QEMU，FreeBSD 在真实客体系统内构建和测试。
测试密钥、样本、日志、结果和构建中间文件不进入附件。

WSEA v2 容器与 13 种算法不变。支持至多八个不同密钥的混合多签。
WASM 只使用 Preview 1 / MVP，无 WASIp2；UWVM 执行前校验仍离线、显式启用。
浏览器宿主必须保护可信策略及防回退快照，SDK 成功不替代 VM 的 --secure 执行授权。
Web GUI 发布检查包含 21 项信息隔离测试、102 项实际程序检查和前端状态流程测试。
原生文件对话框与浏览器布局不属于自动状态测试覆盖范围。

## English

This release merges 24 commits from [official cosign upstream](https://github.com/sigstore/cosign/commit/{upstream})
and upgrades the release toolchain to Go 1.27.3. An independent local Python Web GUI
provides bilingual signing, verification, multisignatures, policies and HTTPS retrieval.
System dialogs select files; only necessary JSON results reach the page.

Complete matching zh_CN / en_US documentation covers the native CLI, WSEA
security rules, multi-signatures and key/version rotation, WASIp1, browser / Node
SDKs, building, testing and CI/CD. [English documentation]({base}/README.en_US.md)

Fifteen targets: static Linux AArch64, ARMv7 hard-float, i686, LoongArch64,
MIPS64 big/little endian, PowerPC64 LE, RISC-V64, x86_64 GNU/musl; FreeBSD 15.1+
x86_64; macOS 15+ AArch64/x86_64; wasm32-wasip1 and wasm32-js. Every archive includes both
documentation languages, licenses and source provenance. A separate `webgui` archive requires
an existing native binary and Python 3.10+ with Zenity or Tk; it never compiles the binary.
SHA256SUMS covers all 16 archives.

Publication requires 277 corpus cases and 76 signing/interoperability checks on
real UWVM, Wasmtime and Node, 13 host-security checks, native product tests,
paired-source checks and strict MVP validation. Linux and FreeBSD/QEMU qualification
use a 64 GiB zero-swap cgroup; macOS runs natively on the matching hosted architecture.
Every additional native target runs the full product tests, using actual QEMU for
Linux cross builds and a real FreeBSD guest for FreeBSD builds and tests.
Generated keys, fixtures, logs, reports and build intermediates are excluded.

The WSEA v2 container and all 13 algorithm profiles are unchanged, including mixed
quorums of up to eight distinct keys. WASM remains Preview 1 / MVP, with no WASIp2.
UWVM's execution gate remains offline and explicit. Browser hosts must protect
trusted policy and rollback snapshots; an SDK result is not --secure VM authorization.
Web GUI publication checks include 21 information-boundary tests, 102 real-command
checks and a frontend state/HTTP flow test. These automated state tests do not
cover native-dialog rendering or browser layout.
''')
