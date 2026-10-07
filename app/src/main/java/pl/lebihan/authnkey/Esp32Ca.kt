package pl.lebihan.authnkey

import android.content.Context
import android.util.Base64
import android.util.Log
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.security.spec.ECParameterSpec
import java.security.AlgorithmParameters
import java.math.BigInteger

/**
 * ESP32 设备证书解析与 CA 验签（对齐 physkey-dashboard/totp.html::verifyDevice 与 passless::verify_device）。
 *
 * 证书格式（自定义简单 DER，非 X.509）：
 *   cert    = len(payload)(2B BE) || payload || sig_len(2B BE) || signature(64B raw r||s)
 *   payload = 0x02 || id_len(1B) || deployment_id(id_len) || device_pubkey(65B) || issue_time(8B) || serial(8B)
 *   （兼容旧格式 0x01：无 deployment_id）
 *
 * 验签算法：ECDSA P-256 + SHA-256。固件 espid_sign 输出 raw r||s (P1363)，
 * Android JCA 的 Signature("SHA256withECDSA") 期望 DER；这里统一把 raw 转 DER 再验。
 */
object Esp32Ca {

    private const val TAG = "Esp32Ca"

    data class DeviceCert(
        val devicePub: ByteArray,   // 65 字节未压缩点 (0x04||X||Y)
        val deploymentId: String,   // 部署标识（内嵌于证书；旧格式为空）
        val issueTime: Long,
        val serial: Long,
    )

    /**
     * 用 CA 公钥验签设备证书，成功返回解析出的设备证书信息。
     * @throws SecurityException 验签失败 / 格式异常
     */
    fun verifyCert(caPubBytes: ByteArray, certDer: ByteArray): DeviceCert {
        if (caPubBytes.size < 65 || caPubBytes[0] != 0x04.toByte()) {
            throw SecurityException("CA 公钥格式异常（应为 65B 未压缩点）")
        }
        if (certDer.size < 4) throw SecurityException("证书过短")

        val plen = ((certDer[0].toInt() and 0xFF) shl 8) or (certDer[1].toInt() and 0xFF)
        if (certDer.size < 2 + plen + 2) throw SecurityException("证书 payload 长度越界")
        val payload = certDer.copyOfRange(2, 2 + plen)

        val sOff = 2 + plen
        val slen = ((certDer[sOff].toInt() and 0xFF) shl 8) or (certDer[sOff + 1].toInt() and 0xFF)
        if (certDer.size < sOff + 2 + slen) throw SecurityException("证书签名长度越界")
        val rawSig = certDer.copyOfRange(sOff + 2, sOff + 2 + slen)
        if (slen != 64) throw SecurityException("证书签名长度异常: $slen")

        if (payload.isEmpty()) throw SecurityException("证书 payload 异常")

        // 解析 payload（兼容 0x01/0x02/0x10）
        val ver = payload[0].toInt() and 0xFF
        val deploymentId: String
        val pubOff: Int
        when (ver) {
            0x02, 0x10 -> {
                val idLen = payload[1].toInt() and 0xFF
                if (payload.size < 2 + idLen + 81) throw SecurityException("证书 payload 异常")
                deploymentId = String(payload, 2, idLen, Charsets.UTF_8)
                pubOff = 2 + idLen
            }
            0x01 -> {
                deploymentId = ""
                pubOff = 1
            }
            else -> throw SecurityException("未知证书格式版本: 0x%02x".format(ver))
        }
        if (payload.size < pubOff + 81) throw SecurityException("证书 payload 异常")
        val subjectPub = payload.copyOfRange(pubOff, pubOff + 65)

        // 用 CA 公钥验签 payload
        val caKey = sec1ToPublicKey(caPubBytes)
        val derSig = rawToDer(rawSig)
        if (!ecdsaVerify(caKey, payload, derSig)) {
            throw SecurityException("证书验签失败：非可信 CA 签发（可能被伪造/中间人）")
        }

        val issueTime = beLong(payload, pubOff + 65)
        val serial = beLong(payload, pubOff + 73)
        Log.i(TAG, "证书验签通过，部署标识='$deploymentId'")
        return DeviceCert(subjectPub, deploymentId, issueTime, serial)
    }

    /**
     * 三级链验签（全程离线，仅用内置根 CA 公钥）：
     *   根CA公钥 → 验中间CA证书（0x10）→ 取中间CA公钥 → 验设备证书（0x02）。
     * @param rootPubBytes 根 CA 公钥（客户端内置）
     * @param deviceCertDer 设备证书（0x02）
     * @param userCaCertDer 中间 CA 证书（0x10）
     * 成功返回设备证书信息（含 deployment_id）。
     */
    fun verifyChain(
        rootPubBytes: ByteArray,
        deviceCertDer: ByteArray,
        userCaCertDer: ByteArray,
    ): DeviceCert {
        // 1) 用根 CA 公钥验中间 CA 证书
        val userCa = verifyCert(rootPubBytes, userCaCertDer)
        // userCa.subjectPub 即中间 CA 公钥
        // 2) 用中间 CA 公钥验设备证书
        val device = verifyCert(userCa.devicePub, deviceCertDer)
        Log.i(TAG, "三级链验签通过：根CA→中间CA('${userCa.deploymentId}')→设备('${device.deploymentId}')")
        return device
    }

    /**
     * 用设备公钥校验挑战响应签名（AUTH 命令返回的 raw r||s）。
     */
    fun verifyChallenge(devicePub: ByteArray, nonce: ByteArray, rawSig: ByteArray): Boolean {
        val key = sec1ToPublicKey(devicePub)
        return ecdsaVerify(key, nonce, rawToDer(rawSig))
    }

    // ---- 内部工具 ----

    private fun ecdsaVerify(pub: java.security.PublicKey, data: ByteArray, derSig: ByteArray): Boolean {
        return try {
            val sig = Signature.getInstance("SHA256withECDSA")
            sig.initVerify(pub)
            sig.update(data)
            sig.verify(derSig)
        } catch (e: Exception) {
            Log.e(TAG, "验签异常", e)
            false
        }
    }
    /** SEC1 未压缩点 (0x04||X||Y) → java ECPublicKey */
    private fun sec1ToPublicKey(point: ByteArray): java.security.PublicKey {
        require(point.size == 65 && point[0] == 0x04.toByte()) { "非法 SEC1 点" }
        val x = BigInteger(1, point.copyOfRange(1, 33))
        val y = BigInteger(1, point.copyOfRange(33, 65))
        val params = AlgorithmParameters.getInstance("EC")
        params.init(ECGenParameterSpec("secp256r1"))
        val ecSpec = params.getParameterSpec(ECParameterSpec::class.java)
        val kf = KeyFactory.getInstance("EC")
        return kf.generatePublic(ECPublicKeySpec(ECPoint(x, y), ecSpec))
    }

    /** raw (r||s) 64B → DER ECDSA 签名（供 CTAP 应答签名转换复用） */
    fun rawToDer(raw: ByteArray): ByteArray {
        require(raw.size == 64) { "raw 签名长度应为 64" }
        val r = BigInteger(1, raw.copyOfRange(0, 32))
        val s = BigInteger(1, raw.copyOfRange(32, 64))
        val rb = r.toByteArray()
        val sb = s.toByteArray()
        val len = 2 + rb.size + 2 + sb.size
        val out = ByteArray(2 + len)
        var i = 0
        out[i++] = 0x30
        out[i++] = len.toByte()
        out[i++] = 0x02
        out[i++] = rb.size.toByte()
        System.arraycopy(rb, 0, out, i, rb.size); i += rb.size
        out[i++] = 0x02
        out[i++] = sb.size.toByte()
        System.arraycopy(sb, 0, out, i, sb.size)
        return out
    }

    private fun beLong(b: ByteArray, off: Int): Long {
        var v = 0L
        for (i in 0 until 8) v = (v shl 8) or (b[off + i].toLong() and 0xFF)
        return v
    }
}
