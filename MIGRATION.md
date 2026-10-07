# Authnkey-ESP32 魔改说明

把 [Authnkey](https://github.com/mimi89999/Authnkey)（Android FIDO2/CTAP2 凭据提供者）的后端
从“NFC / USB-HID 直连安全密钥”改为**经 BLE NUS 转发给 ESP32 硬件认证器**，
与 `esp32c5-totp` 固件、`physkey-dashboard/*.html`、`passless` 使用**同一套私有 NUS 文本协议**与**同一套 CA 信任链**。

> 保留上游 MIT 许可。本目录为魔改分支，改动集中在下述新增/修改文件。

## 设计目标

1. **密钥永不出芯片**：注册（`WA_REG`）与签名（`WA_SIGNHASH`/`WA_WEBSIGNSHASH`）全部在 ESP32 完成。
2. **复用 Authnkey 全套 UI / 凭据选择 / 多账号流程**，只替换传输层与认证后端。
3. **不漏流程**：CA 信任链校验、解锁（口令）、BLE 分帧协议、CTAP2 ↔ NUS 翻译、掉电重锁，
   全部对齐 `physkey-linux/cmd/passless/src/esp32.rs` 与 `physkey-dashboard/totp.html` 的既有实现。

## 三个关键决策（已与主人确认）

| 决策 | 选择 |
|------|------|
| PIN 流程 | **省事版**：不实现 CTAP2 clientPin，改为口令 → `AUTHPASS` 解锁 |
| CA 公钥 | **硬编码**在 `Esp32Config.kt`（可被设置覆盖） |
| BLE 设备名 | **运行时可配置**，不写死 `ATRI-TOTP`；默认按昵称前缀 `ATRI` 匹配 |

## 改动清单

### 新增文件

| 文件 | 作用 |
|------|------|
| `Esp32Config.kt` | 设备名/前缀、CA 公钥、NUS UUID、超时等常量与持久化设置 |
| `Esp32Protocol.kt` | NUS 文本协议客户端：连接、分帧收发、CA 验签、解锁、翻译表 |
| `Esp32Transport.kt` | `FidoTransport` 实现，被 `CtapSession.attach()` 复用 |
| `Esp32DeviceInfo.kt` | 本地构造的 `DeviceInfo`（AAGUID=ATRI，`clientPin=false`） |
| `Esp32Ca.kt` | 证书解析 + P1363/DER ECDSA P-256 验签（Java/JCA） |
| `Esp32Bridge.kt` | 关键：`sendCtapCommand()` 的中枢，CTAP2 命令 ↔ NUS 翻译 |

### 修改文件（相对上游）

| 文件 | 改动 |
|------|------|
| `CtapSession.kt` | `attach()` 对 ESP32 传输直接使用 `Esp32DeviceInfo.get()`（不发 GetInfo） |
| `CredentialProviderActivity.kt` | 增加 ESP32 连接入口；口令输入复用现有 `onPinEntered` → 走 `AUTHPASS` |
| `TransportHints.kt` | 增加 BLE 可用性提示（替代/补充 NFC·USB） |
| `AndroidManifest.xml` | 加 `BLUETOOTH_SCAN` / `BLUETOOTH_CONNECT` 权限与 `bluetooth_le` feature |
| `app/build.gradle.kts` | 无新三方依赖（JCA 自带 ECDSA；必要时再评估 BouncyCastle） |

## 流程对齐要点

### 1. CA 信任链（对齐 passless `verify_device` / web `verifyDevice`）

```
GETCERT → cert
  cert = len(2) || payload || slen(2) || sig(64)     (大端)
  payload = 0x01 || devicePub(65) || issue_time(8) || serial(8)
  devicePub = payload[1..66]
用内置 CA 公钥（P-256 未压缩点）验签 payload(签名 sig, SHA-256)
AUTH <nonce32> → SIG
用 devicePub 验签 nonce
任一失败 → 拒绝连接（防中间人）
```

> 固件 `espid_sign` 输出 **raw r||s (P1363)**；验签时转 DER 或用 P1363 验签均可。

### 2. 解锁（`HASPASS` / `AUTHPASS`）

- 连接后先 `HASPASS` 判断是否已设密码，决定 UI 文案。
- 口令通过 `AUTHPASS <pw>` 下发；成功置 `unlocked=true` 缓存。
- **断连/掉电即上锁**（固件在 disconnect 时 `esp_crypto_lock()`），重连需重新解锁。
- 仅在收到精确的 `ERR locked` / `engine locked` / `not unlocked` 时清缓存；
  **不可**用 `contains("locked")`（会误伤 `not found or locked`）。

### 3. BLE 分帧（对齐 web `send()` / passless `BleLink::command`）

- 发送：`命令体 + '\n'`，前置 **4 位十六进制长度**（长度 = 命令体字节数），
  按 **20 字节分片**，**不切在多字节 UTF-8 字符中间**，片间延时 8~25ms。
- 接收：固件分包 notify，需累积到 `\n` 切行；收到 `OK`/`ERR` 起始行后继续等待，
  **静默 500ms** 无新分片才认为收完（长响应如 `WA_REG` 的 `OK CRED`+`PUBKEY`）。

### 4. CTAP2 ↔ NUS 翻译表

| CTAP2 命令 | → NUS | 说明 |
|-----------|-------|------|
| `GetInfo(0x04)` | 本地构造 | AAGUID=ATRI；`options.rk=true`、`clientPin=false`、`uv=false`；`versions=["FIDO_2_1"]` |
| `MakeCredential(0x01)` | `WA_REG` + `WA_SETMETA` | 拼 authData（AT 标志 + 16B credId + COSE 公钥），attStmt 空 |
| `GetAssertion(0x02)` | `WA_LIST`/`WA_META` + `WA_WEBSIGNHASH` | 用 rpIdHash + sig 拼 authData |
| `GetNextAssertion(0x08)` | `WA_LIST` 迭代 | 多凭据选择依赖此命令 |
| `ClientPin(0x06)` | **改造** → `AUTHPASS` | 省事版：不走 ECDH/PIN，见下 |

### 5. PIN 省事版说明

由于 `DeviceInfo.options.clientPin=false`，Authnkey 的 `processRequest()` 会走
“No verification method available / tryExecuteWithoutPin” 分支。
我们在 `CredentialProviderActivity` 挂一个口令输入（复用 `CredentialBottomSheet` 的 PIN 输入框），
把用户输入当作设备口令发 `AUTHPASS`，成功即视为“已解锁”，随后正常下发翻译后的 CTAP 命令。
即：**PIN 输入 = 设备口令**，不再需要 CTAP2 的 ECDH key agreement。

## 待办 / 后续

- [ ] `Esp32Bridge` 各命令的完整实现与单元测试
- [ ] 设备名/前缀的设置界面（MainActivity）
- [ ] 与 `esp32c5-totp` 固件联调（CA 公钥用 `tools/atri-ca.py capub` 生成的值替换）
- [ ] 多账号 `GetNextAssertion` 的实测
- [ ] 是否需要对 USB/NFC 传输保留（当前保留上游实现，未删除）

## 构建

```
./gradlew assembleDebug
```

要求：Android 14+（API 34），与上游一致。
