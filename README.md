<h1 align="center">
  <br>
  <img src="app/src/main/res/mipmap-anydpi-v26/ic_launcher.xml" alt="logo" width="180" onerror="this.style.display='none'">
  <br>
  physkey-android
  <br>
  <span style="font-size:0.7em;color:#888;">Passkey (FIDO2) · ESP32 BLE · Android 凭据提供者</span>
  <br><br>
</h1>

![Kotlin](https://img.shields.io/badge/kotlin-1.9%2B-007396?logo=kotlin)
![Android](https://img.shields.io/badge/Android-14%2B-3DDC84?logo=android)
![Rust](https://img.shields.io/badge/rust-android%20cross-compile-000000?logo=rust)
![License](https://img.shields.io/badge/license-MIT-blue)
![Backend](https://img.shields.io/badge/backend-ESP32--C5--BLE-orange)

**physkey-android** 是把 **ESP32 变成 Android 系统级 FIDO2 硬件安全密钥** 的凭据提供者应用。
它实现 Android `CredentialProvider` API（Android 14+），系统将 passkey 注册 / 认证请求路由给它；
应用内部通过 Nordic UART Service (NUS) 蓝牙协议，把密钥生成和 P-256 签名安全转发给 ESP32 硬件——**私钥永不离开设备**。

与 physkey-linux（Linux 桌面版）使用同一套 ESP32 协议栈和核心逻辑，两端注册的凭据**互相可见、可交叉认证**。

---

## 架构

```
┌────────────────────────────────────────────────────────────────┐
│                 Android 系统 / WebAuthn                          │
│   Google Password Manager · 浏览器 · 第三方应用                  │
└──────────────────────────┬─────────────────────────────────────┘
                           │ AndroidX CredentialManager API
                           ▼
┌────────────────────────────────────────────────────────────────┐
│  physkey-android (Kotlin)                                       │
│                                                                │
│   ┌──────────────────┐    ┌───────────────────────────┐        │
│   │ CTAP2 编解码      │    │  BLE NUS 传输层            │        │
│   │ CborEncoder/Dec. │◄──►│ BluetoothGatt + NUS UUIDs  │        │
│   └────────┬─────────┘    └─────────┬─────────────────┘        │
│            │                         │                          │
│   ┌────────▼─────────────────────────▼──────────┐              │
│   │   libesp32_fido_core.so (Rust JNI)           │              │
│   │   cmd_wa_reg_placeholder / cmd_sign_digest   │              │
│   │   cmd_wa_setmeta[_web] / generate_cred_id   │              │
│   └────────────────────┬─────────────────────────┘              │
│                        │ NUS 文本协议                          │
└────────────────────────┼──────────────────────────────────────┘
                         │ 蓝牙 BLE
                         ▼
          ┌─────────────────────────────┐
          │  ESP32 硬件              │
          │  (私钥永不导出)             │
          │                             │
          │  WA_REG    密钥生成         │
          │  WA_SIGNHASH / WA_WEBSIGNHASH  P-256 签名
          │  WA_LIST / WA_META  凭证   │
          │  GETCERT / AUTH  信任链     │
          │  AUTHPASS  解锁口令        │
          └─────────────────────────────┘
```

### 数据通路

```
应用: CredentialManager.createPublicKeyCredential()
  → Android CredentialProviderActivity
  → Esp32Transport.makeCredential()
  → WA_REG esp32 user\n  (BLE)
  → ESP32 生成 P-256 密钥对 → 返回 内部 ID + 公钥
  → Android 生成 32B random credentialId，发 WA_SETMETA + WA_SETMETA_WEB 双索引
  → 组装 CTAP2 MakeCredential 响应 → 系统返回给应用 ✅
```

```
应用: CredentialManager.getCredential()
  → Android CredentialProviderActivity
  → Esp32Transport.getAssertion()
  → WA_WEBSIGNHASH <allowList-webid> <sha256>   (主路径)
  → ESP32 内部签名 → 返回 64B raw (r||s)
  → 如失败：WA_LIST 按 rpId 查候选 → WA_META 回读 webid → 精确匹配
  → 转 DER 编码，组装 CTAP2 GetAssertion 响应 ✅
```

---

## 功能清单

| 功能 | 状态 | 说明 |
|------|------|------|
| FIDO2 / WebAuthn CTAP2 合规 | ✅ | 手写 CTAP2 CBOR 编解码 |
| Android Credential Provider | ✅ | Android 14+ 系统级接入 |
| Passkey (resident credential) | ✅ | `rk=true`，支持自动填充 |
| 硬件密钥生成（P-256 ES256） | ✅ | 私钥锁死在 ESP32 |
| 硬件签名 | ✅ | SHA-256 摘要 + P-256 raw 签名 |
| 凭证全存储在设备端 | ✅ | 手机本地不落盘 |
| 双端凭据互通 | ✅ | 与 physkey-linux 注册的凭据互相可见 |
| 信任链校验 | ✅ | CA 证书 + 挑战响应 |
| BLE NUS 协议 | ✅ | Nordic UART Service 文本行协议 |

### 已知限制

- **仅支持 P-256 (ES256)**
- **仅 BLE 连接**，无 NFC / USB HID
- **Android 14+ (API 34)**，使用 `androidx.credentials`
- **无 PIN / UV 界面**（依赖系统 CredentialManager 流程）

---

## 编译

### 先决条件

```bash
# Android SDK（Android Studio 安装，或命令行 tools）
export ANDROID_HOME=~/Android/Sdk

# Android NDK r27+（build.gradle 引用）
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/<version>

# Rust + Android targets
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android

# cargo-ndk（Rust → Android .so 交叉编译）
cargo install cargo-ndk

# 蓝牙依赖
# physkey-linux/esp32-fido-core 路径是 build.gradle.kts 写死的
#   val rustCrateDir = rootDir.resolve("../physkey-linux/esp32-fido-core")
#   val rustWorkspaceDir = rootDir.resolve("../physkey-linux")
# → physkey-android/ 和 physkey-linux/ 必须位于同一父目录下
```

### 编译 Rust 核心库（独立步骤，可选）

```bash
cd physkey-android/

# 手动触发 Rust .so 编译 + 复制到 jniLibs
./gradlew buildRustLib
# 输出:
# [rust] installed libesp32_fido_core.so → arm64-v8a/ (xxxx bytes)
# [rust] installed libesp32_fido_core.so → armeabi-v7a/ (xxxx bytes)
# [rust] installed libesp32_fido_core.so → x86_64/ (xxxx bytes)
```

产物位置：`physkey-android/app/src/main/jniLibs/<abi>/libesp32_fido_core.so`

### 编译 APK（包含 Rust 库）

```bash
# assembleDebug / assembleRelease 自动依赖 buildRustLib
./gradlew assembleDebug

# Release 构建（带混淆）
./gradlew assembleRelease
```

产物位置：`physkey-android/app/build/outputs/apk/<buildType>/`

### 一键编译 & 安装到设备

```bash
./gradlew installDebug
adb logcat -s Esp32Bridge RustJni
```

---

## 安装与配置

1. **安装 APK**：`./gradlew installDebug` 或直接 adb 安装生成的 apk
2. **启用凭据提供者**：设置 → 密码和凭据 → 密码、密钥和数据服务 → physkey-android
3. **首次配对**：应用启动时扫描 ESP32 设备（广播名 `ATRI-TOTP`，可在 Esp32Transport 中修改）
4. **浏览器验证**：打开 `https://webauthn.io/` → 注册 passkey → 选择"安全密钥"或 physkey-android

### ESP32 固件要求

与 physkey-linux 完全一致，需要实现 Nordic UART Service 文本协议：

```
RX: 6e400002-b5a3-f393-e0a9-e50e24dcca9e
TX: 6e400003-b5a3-f393-e0a9-e50e24dcca9e

WA_REG <rp> [user]                      → OK CRED:<id_hex> + PUBKEY:<pub_b64>
WA_SIGNHASH <id_hex> <sha256b64>        → OK SIG:<sig_b64>
WA_WEBSIGNHASH <webid_b64> <sha256b64>  → OK SIG:<sig_b64>
WA_LIST                                 → 每行 "id_hex\trp\tuser" + OK
WA_META <id_hex>                        → key=value...
WA_WEBMETA <webid_b64>                  → key=value...
WA_SETMETA <id_hex> <kvs>               → OK / ERR
WA_SETMETA_WEB <webid_b64> <kvs>        → OK / ERR
AUTHPASS / GETCERT / AUTH               → 信任链相关
```

固件仓库：`esp32c5-totp/`（同仓库内）

---

## 调试

```bash
# 1) Rust .so 是否正确加载
adb logcat -s RustJni

# 2) ESP32 BLE 通信日志（包含 WA_REG / WA_WEBSIGNHASH 原始命令和响应）
adb logcat -s Esp32Bridge

# 3) 检查 jniLibs 中是否有 .so 文件
find physkey-android/app/src/main/jniLibs -name "*.so"

# 4) 手动重新编译 Rust 库（排除 Gradle 缓存问题）
./gradlew clean buildRustLib assembleDebug

# 5) 用 Android Studio 的 Logcat 过滤 "Esp32Bridge" 看 WebAuthn 注册/认证完整流程
```

常见问题：

| 报错 | 原因 | 解决 |
|------|------|------|
| `未找到 ANDROID_NDK_HOME 或 ndk.dir` | 没配置 NDK 路径 | 设置 `ANDROID_NDK_HOME` 或在 `local.properties` 写 `ndk.dir=...` |
| `cargo ndk build failed for aarch64-linux-android` | cargo-ndk 未安装或 Rust target 缺失 | `cargo install cargo-ndk` + `rustup target add ...` |
| `esp32-fido-core` 编译找不到 | `physkey-linux/` 和 `physkey-android/` 不在同一父目录 | 确认目录结构 |
| `ESP32 连接失败` | 蓝牙未开 / 设备名不匹配 | logcat 看 Esp32Bridge 扫描日志 |
| `WA_WEBSIGNHASH ERR` | 固件未建立 webid 索引 | 确认注册时发了 `WA_SETMETA_WEB`，或清理旧凭据重注册 |

---

## 项目结构

```
physkey-android/
├── app/src/main/
│   ├── java/pl/lebihan/authnkey/
│   │   ├── CredentialProviderActivity.kt   # Android 系统入口
│   │   ├── Esp32Transport.kt               # CTAP2 → ESP32 命令翻译
│   │   ├── rust/
│   │   │   └── Esp32Core.kt                # Rust JNI 声明
│   │   └── ...
│   └── jniLibs/
│       ├── arm64-v8a/libesp32_fido_core.so    # Gradle buildRustLib 自动生成
│       ├── armeabi-v7a/libesp32_fido_core.so
│       └── x86_64/libesp32_fido_core.so
├── build.gradle.kts                       # buildRustLib task + Rust 路径硬编码
├── settings.gradle.kts
└── README.md
```

Rust 核心实现位于 **sibling workspace** `physkey-linux/esp32-fido-core/`，Android 不直接编译该 crate——
Gradle 任务调用 `cargo ndk --features jni` 把它交叉编译为 Android `.so`。

---

## 双端互通说明

physkey-android 和 physkey-linux 共享同一 ESP32 固件和 `esp32-fido-core` 协议库。
两端**注册的凭据互相可见**的关键：

1. **注册路径双索引**：两端都发 `WA_SETMETA`（内部 ID 索引）+ `WA_SETMETA_WEB`（webid 索引）
2. **认证路径双路**：
   - 主路径：`WA_WEBSIGNHASH <allowList-webid>`
   - Fallback：`WA_LIST` 按 rpId 搜索 → `WA_META` 回读 webid 精确匹配
3. **清理旧凭据**：如果固件上有**注册时只发了 WA_SETMETA 没发 WA_SETMETA_WEB** 的旧凭据，
   建议清空重注册（`WA_DEL` / 固件擦除）

---

## 致谢

基于 [Authnkey](https://github.com/OpenSC/authnkey) 原项目改造，移除 NFC/USB 传输层，
替换为 ESP32 BLE NUS 桥接；CTAP2 编解码复用 [passless](https://github.com/pando85/passless)
的 Rust 核心库（`esp32-fido-core`）。