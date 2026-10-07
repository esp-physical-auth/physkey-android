package pl.lebihan.authnkey

/**
 * CTAP2 请求/应答的 CBOR 编解码（ESP32 桥专用）。
 *
 * 只覆盖 ESP32 后端用到的字段子集；完整 CTAP2 编解码仍由 FidoCommands/CTAP 体系负责，
 * 这里仅做"CTAP2 命令 ↔ 设备能力"的最小拼接（见 MIGRATION.md 翻译表）。
 */
object CtapRequest {

    data class MakeCredential(
        val clientDataHash: ByteArray,
        val rpId: String,
        val rpName: String?,
        val userId: ByteArray,
        val userName: String?,
        val userDisplayName: String?,
        val requireResidentKey: Boolean,
        val uv: Boolean,
    )

    data class AllowEntry(val type: String, val id: ByteArray)

    data class GetAssertion(
        val rpId: String,
        val clientDataHash: ByteArray,
        val allowList: List<AllowEntry>,
        val uv: Boolean,
    ) {
        val user: CtapResponse.UserRef? get() = null
    }

    @Suppress("UNCHECKED_CAST")
    fun parseMakeCredential(payload: ByteArray): MakeCredential? {
        val map = CborDecoder.decode(payload) as? Map<*, *> ?: return null
        val clientDataHash = map[1L] as? ByteArray ?: return null
        val rp = map[2L] as? Map<*, *> ?: return null
        val rpId = rp["id"] as? String ?: return null
        val rpName = rp["name"] as? String
        val user = map[3L] as? Map<*, *> ?: return null
        val userId = user["id"] as? ByteArray ?: return null
        val userName = user["name"] as? String
        val userDisplayName = user["displayName"] as? String
        val opts = map[7L] as? Map<*, *>
        val rk = opts?.get("rk") as? Boolean ?: false
        val uv = opts?.get("uv") as? Boolean ?: false
        return MakeCredential(clientDataHash, rpId, rpName, userId, userName, userDisplayName, rk, uv)
    }

    @Suppress("UNCHECKED_CAST")
    fun parseGetAssertion(payload: ByteArray): GetAssertion? {
        val map = CborDecoder.decode(payload) as? Map<*, *> ?: return null
        val rpId = map[1L] as? String ?: return null
        val clientDataHash = map[2L] as? ByteArray ?: return null
        val allowList = ((map[3L] as? List<*>) ?: emptyList<Any?>()).mapNotNull { e ->
            val m = e as? Map<*, *> ?: return@mapNotNull null
            val id = m["id"] as? ByteArray ?: return@mapNotNull null
            val type = m["type"] as? String ?: "public-key"
            AllowEntry(type, id)
        }
        val opts = map[5L] as? Map<*, *>
        val uv = opts?.get("uv") as? Boolean ?: false
        return GetAssertion(rpId, clientDataHash, allowList, uv)
    }
}

object CtapResponse {

    data class UserRef(val id: ByteArray, val name: String?, val displayName: String?)

    /** CTAP2 MakeCredential 应答： 0x00 || CBOR{1:fmt, 2:authData, 3:attStmt} */
    fun makeCredential(fmt: String, attStmt: Map<Int, Any?>, authData: ByteArray): ByteArray {
        val body = cbor {
            map {
                1 to fmt
                2 to bytes(authData)
                3 to map { for ((k, v) in attStmt) k to v }
            }
        }
        return byteArrayOf(0x00) + body
    }

    /** CTAP2 GetAssertion 应答： 0x00 || CBOR{1:credential, 2:authData, 3:signature, 4:user?} */
    fun getAssertion(
        credentialId: ByteArray,
        authData: ByteArray,
        signature: ByteArray,
        user: UserRef?,
    ): ByteArray {
        val body = cbor {
            map {
                1 to map {
                    "type" to "public-key"
                    "id" to bytes(credentialId)
                }
                2 to bytes(authData)
                3 to bytes(signature)
                if (user != null) {
                    4 to map {
                        "id" to bytes(user.id)
                        if (user.name != null) "name" to user.name
                        if (user.displayName != null) "displayName" to user.displayName
                    }
                }
            }
        }
        return byteArrayOf(0x00) + body
    }

    /**
     * 拼 authenticatorData（注册）： rpIdHash(32) || flags(1) || signCount(4) || attestedCredData
     * attestedCredData = aaguid(16) || credIdLen(2) || credId || cosePublicKey
     */
    fun buildAuthDataCreate(rpIdHash: ByteArray, credentialId: ByteArray, coseKey: ByteArray): ByteArray {
        val flags = (0x01 or 0x40).toByte() // UP | AT
        val out = mutableListOf<Byte>()
        out.addAll(rpIdHash.toList())
        out.add(flags)
        out.addAll(byteArrayOf(0, 0, 0, 0).toList()) // signCount = 0
        out.addAll(ATRI_AAGUID.toList())
        out.add((credentialId.size shr 8).toByte())
        out.add((credentialId.size and 0xFF).toByte())
        out.addAll(credentialId.toList())
        out.addAll(coseKey.toList())
        return out.toByteArray()
    }

    private val ATRI_AAGUID = byteArrayOf(
        0x41, 0x54, 0x52, 0x49, 0x2D, 0x43, 0x35, 0x2D,
        0x30, 0x30, 0x30, 0x31, 0x00, 0x00, 0x00, 0x00,
    )
}

/** COSE 公钥编码辅助。 */
object Cose {
    /**
     * 由 SEC1 未压缩点 (0x04||X||Y, 65B) 构造 ES256 的 COSE_Key 字节。
     * COSE_Key = CBOR map { 1(kty):2(EC2), 3(alg):-7, -1(crv):1(P-256), -2(x):bstr, -3(y):bstr }
     */
    fun encodeEs256(sec1: ByteArray): ByteArray? {
        if (sec1.size != 65 || sec1[0] != 0x04.toByte()) return null
        val x = sec1.copyOfRange(1, 33)
        val y = sec1.copyOfRange(33, 65)
        return cbor {
            map {
                1 to 2      // kty = EC2
                3 to -7     // alg = ES256
                (-1) to 1   // crv = P-256
                (-2) to bytes(x)
                (-3) to bytes(y)
            }
        }
    }
}
