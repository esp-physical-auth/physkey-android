package pl.lebihan.authnkey.rust

object Esp32Core {
    init {
        try {
            System.loadLibrary("esp32_fido_core")
        } catch (_: Throwable) {
        }
    }

    external fun cmdWaReg(rp: String, user: String): String
    external fun parseWaRegResponse(resp: String): String?
    external fun cmdSignHash(keyMaterial: ByteArray, message: ByteArray): String
    external fun cmdSignDigest(keyMaterial: ByteArray, digest: ByteArray): String
    external fun parseSignResponse(resp: String): ByteArray?
    external fun cmdDelete(keyMaterial: ByteArray): String
    external fun rawSigToDer(raw: ByteArray): ByteArray?
    external fun hexOf(bytes: ByteArray): String
    external fun bytesOfHex(hex: String): ByteArray?
    external fun cmdWaPub(idHex: String): String
    external fun parseWaPubResponse(resp: String): ByteArray?
    external fun generateCredentialId(): ByteArray
    external fun cmdWaRegPlaceholder(): String
    external fun cmdWaSetMeta(
        idHex: String,
        created: Long,
        signCount: Int,
        alg: Int,
        credProtect: Byte,
        discoverable: Byte,
        backupState: Byte,
        userId: ByteArray,
        userDisplay: ByteArray,
        webid: ByteArray,
        rp: ByteArray,
        user: ByteArray,
    ): String

    external fun cmdWaSetMetaWeb(
        webid: ByteArray,
        created: Long,
        signCount: Int,
        alg: Int,
        credProtect: Byte,
        discoverable: Byte,
        backupState: Byte,
        userId: ByteArray,
        userDisplay: ByteArray,
        rp: ByteArray,
        user: ByteArray,
    ): String

    fun available(): Boolean = this::class.java.classLoader != null
}