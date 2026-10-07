package pl.lebihan.authnkey

import android.content.Context
import android.util.Base64

/**
 * ESP32 后端配置。
 *
 * ⚠️ 魔改说明（见 MIGRATION.md）：
 *  - 后端由 NFC/USB 直连改为经 BLE NUS 转发给 ESP32 硬件认证器。
 *  - 根 CA 公钥【硬编码】（与 physkey-dashboard/totp.html 的 ROOT_CA_PUBKEY_B64 同源，可用设置覆盖）。
 *    验签链：根CA→中间CA→设备，全程离线（不写死域名/IP、不联网）。
 *  - BLE 设备名【运行时可配置】，不写死 "ATRI-TOTP"。
 */
object Esp32Config {

    // ---- BLE 设备识别 ----
    //
    // 固件端广播名是编译期宏 BLE_DEVICE_NAME（main/ble_totp.h），默认 "ATRI-TOTP"，
    // 但主人可能改成任意名字。web 用 namePrefix "ATRI" 匹配，passless 用运行时 --esp32-device-name。
    // 这里同样支持两种模式：
    //   - deviceName 非空 → 精确匹配（equals）
    //   - deviceName 为空 → 用 namePrefix 前缀匹配（默认 "ATRI"）
    const val DEFAULT_NAME_PREFIX = "ATRI"

    // ---- Nordic UART Service (NUS) ----
    const val NUS_SERVICE_UUID = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
    const val NUS_RX_UUID = "6e400002-b5a3-f393-e0a9-e50e24dcca9e" // 写入命令
    const val NUS_TX_UUID = "6e400003-b5a3-f393-e0a9-e50e24dcca9e" // 订阅通知
    const val NUS_CCCD_UUID = "00002902-0000-1000-8000-00805f9b34fb"

    // ---- 分包 / 超时（对齐 passless BleLink::command）----
    const val WRITE_CHUNK = 20          // 单次 BLE 写入字节数
    const val CHUNK_DELAY_MS = 15L      // 片间延时
    const val SCAN_TIMEOUT_MS = 15_000L
    const val COMMAND_TIMEOUT_MS = 20_000L
    const val QUIET_WINDOW_MS = 500L    // 收到终止行后的静默收敛窗口

    /**
     * CA 公钥（P-256 未压缩点，base64，65 字节）。
     *
     * 由 `tools/atri-ca.py root-init` 生成后 `atri-ca.py root-pub` 打印，粘到这里。
     * 当前值与 physkey-dashboard/totp.html 中的 ROOT_CA_PUBKEY_B64 保持一致，便于同一根 CA 同时服务网页与 App。
     * 公钥公开安全：没有根 CA 私钥就签不出能被验过的证书。
     * 验签全程离线：不写死域名/IP、不联网。
     */
    const val DEFAULT_CA_PUBKEY_B64 =
        "BO+1Mjj2ZeglAd76ArgCaujE0FdBr+TURI6nlaMaAYAN7pZN04F3yhqzxGhDalco5cGMqSdVtgUT9Tu4iFbG9Q0="

    // ---- 运行时可覆盖设置（SharedPreferences）----
    private const val PREFS = "esp32_backend"
    private const val KEY_DEVICE_NAME = "device_name"
    private const val KEY_CA_PUBKEY = "ca_pubkey_b64"

    /** 精确设备名；空串表示按前缀匹配。 */
    fun deviceName(ctx: Context): String =
        prefs(ctx).getString(KEY_DEVICE_NAME, "") ?: ""

    /** 名称前缀（仅当 deviceName 为空时生效）。 */
    fun namePrefix(ctx: Context): String = DEFAULT_NAME_PREFIX

    /** 根 CA 公钥 base64（可被设置覆盖）。 */
    fun caPubkeyB64(ctx: Context): String =
        prefs(ctx).getString(KEY_CA_PUBKEY, DEFAULT_CA_PUBKEY_B64) ?: DEFAULT_CA_PUBKEY_B64

    fun caPubkeyBytes(ctx: Context): ByteArray =
        Base64.decode(caPubkeyB64(ctx), Base64.DEFAULT)

    /** 判断扫描到的设备名是否匹配目标。 */
    fun matches(ctx: Context, advertisedName: String?): Boolean {
        val n = advertisedName ?: return false
        val exact = deviceName(ctx)
        return if (exact.isNotEmpty()) n == exact else n.startsWith(namePrefix(ctx))
    }

    fun setDeviceName(ctx: Context, name: String) {
        prefs(ctx).edit().putString(KEY_DEVICE_NAME, name.trim()).apply()
    }

    fun setCaPubkeyB64(ctx: Context, b64: String) {
        prefs(ctx).edit().putString(KEY_CA_PUBKEY, b64.trim()).apply()
    }

    private fun prefs(ctx: Context) =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
