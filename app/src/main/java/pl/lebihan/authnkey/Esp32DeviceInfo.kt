package pl.lebihan.authnkey

/**
 * ESP32 后端的 CTAP2 GetInfo 应答（本地构造，不发往设备）。
 *
 * 关键点（见 MIGRATION.md 决策）：
 *  - AAGUID 定制为 ATRI 标识，便于 UI 识别。
 *  - options.clientPin = false  → 让 Authnkey 走"无 PIN"路径，
 *    真正的解锁由 [Esp32Protocol.unlock]（AUTHPASS）承担（PIN 省事版）。
 *  - options.rk = true          → 支持常驻密钥（discoverable credential）。
 *  - options.uv = false         → ESP32 无内置生物识别。
 *  - 仅支持 ES256（alg = -7）。
 */
object Esp32DeviceInfo {

    /** ATRI 的 AAGUID（16 字节，魔改自定为 "ATRI-C5-0001" 的可读编码）。 */
    private val ATRI_AAGUID: ByteArray = byteArrayOf(
        0x41, 0x54, 0x52, 0x49, 0x2D, 0x43, 0x35, 0x2D,  // "ATRI-C5-"
        0x30, 0x30, 0x30, 0x31, 0x00, 0x00, 0x00, 0x00,  // "0001"
    )

    fun get(): DeviceInfo = DeviceInfo(
        versions = listOf("FIDO_2_1", "FIDO_2_0"),
        extensions = emptyList(),          // ESP32 未实现 hmac-secret / credProtect 扩展
        aaguid = Aaguid(ATRI_AAGUID),
        options = mapOf(
            "rk" to true,                  // 常驻密钥
            "up" to true,                  // user presence
            "clientPin" to false,          // 省事版：不使用 CTAP2 PIN
            "uv" to false,                 // 无内置 UV
        ),
        maxMsgSize = 1024,
        pinUvAuthProtocols = emptyList(),
        maxCredentialCountInList = 8,      // 对齐固件 WA_MAX_CREDS
        maxCredentialIdLength = 32,        // 对齐固件 WA_MAX_WEBID
        transports = setOf(TransportType.BLE),
        algorithms = listOf(AlgorithmInfo(type = "public-key", alg = CoseAlgorithm(-7))),
        firmwareVersion = 1,
        minPinLength = null,
        uvModality = null,
    )
}
