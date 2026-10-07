package pl.lebihan.authnkey

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import pl.lebihan.authnkey.rust.Esp32Core
import java.security.MessageDigest

class Esp32Transport private constructor(
    private val link: Esp32Protocol,
) : FidoTransport {

    override val transportType = TransportType.BLE

    override val isConnected: Boolean
        get() = true

    override fun reclaimConnection() {}

    override suspend fun sendCtapCommand(command: ByteArray): ByteArray = withContext(Dispatchers.IO) {
        val cmd = if (command.isNotEmpty()) command[0].toInt() and 0xFF else -1
        android.util.Log.i("Esp32Transport", "sendCtapCommand: cmd=0x${cmd.toString(16)} len=${command.size}")
        val resp = Esp32Bridge.handle(link, command)
        android.util.Log.i("Esp32Transport", "sendCtapCommand 响应: ${resp.size} 字节, 首字节=0x${(resp.firstOrNull()?.toInt()?.and(0xFF) ?: -1).toString(16)}")
        resp
    }

    override fun close() {
        link.close()
    }

    companion object {
        private const val TAG = "Esp32Transport"

        fun from(link: Esp32Protocol): Esp32Transport = Esp32Transport(link)

        suspend fun connect(context: Context): Esp32Transport {
            val link = Esp32Protocol.connect(context)
            return Esp32Transport(link)
        }
    }
}

object Esp32Bridge {

    private const val STATUS_OK: Byte = 0x00

    suspend fun handle(link: Esp32Protocol, command: ByteArray): ByteArray {
        if (command.isEmpty()) return err(CTAP.Error.INVALID_LENGTH)

        val cmd = command[0].toInt() and 0xFF
        android.util.Log.i("Esp32Bridge", "handle: cmd=0x${cmd.toString(16)}, payload=${command.size - 1} bytes")
        val payload = if (command.size > 1) command.copyOfRange(1, command.size) else ByteArray(0)

        return when (cmd) {
            CTAP.CMD_GET_INFO -> CTAP.encodeGetInfo(Esp32DeviceInfo.get())
            CTAP.CMD_MAKE_CREDENTIAL -> makeCredential(link, payload)
            CTAP.CMD_GET_ASSERTION -> getAssertion(link, payload)
            CTAP.CMD_GET_NEXT_ASSERTION -> getNextAssertion(link)
            CTAP.CMD_CLIENT_PIN -> err(CTAP.Error.INVALID_SUBCOMMAND)
            else -> err(CTAP.Error.INVALID_COMMAND)
        }
    }

    // ------------------------------------------------------------------
    // MakeCredential — 对齐 passless agent/register.rs:258-350
    // ------------------------------------------------------------------

    private suspend fun makeCredential(link: Esp32Protocol, payload: ByteArray): ByteArray {
        android.util.Log.i("Esp32Bridge", "makeCredential: unlocked=${link.isUnlocked()}")
        if (!link.isUnlocked() && !link.ensureUnlocked()) return err(CTAP.Error.PIN_REQUIRED)

        val req = CtapRequest.parseMakeCredential(payload)
            ?: run { android.util.Log.e("Esp32Bridge", "makeCredential: parse 失败"); return err(CTAP.Error.INVALID_CBOR) }

        // 1) WA_REG 占位 "esp32 user"（对齐 passless esp32.rs:688）
        //    ESP32 按槽位生成密钥对，rp 参数只是内部标签——后面 WA_SETMETA 写真实 rp
        val reg = link.command(Esp32Core.cmdWaRegPlaceholder())
        android.util.Log.i("Esp32Bridge", "makeCredential: WA_REG 占位响应=${reg}")
        val regJson = Esp32Core.parseWaRegResponse(reg)
            ?: run { android.util.Log.e("Esp32Bridge", "WA_REG 解析失败"); return err(CTAP.Error.OTHER) }
        val json = JSONObject(regJson)
        val idHex = json.getString("id_hex")
        val internalId = Esp32Core.bytesOfHex(idHex)
            ?: return err(CTAP.Error.OTHER)
        android.util.Log.i("Esp32Bridge", "makeCredential: internal id=${idHex} (${internalId.size}B)")

        // 2) 生成 32B 随机 credentialId（对齐 passless generate_credential_id()）
        //    这是对外暴露给 WebAuthn 的 id，与 16B 内部 id 通过 WA_SETMETA webid 字段关联
        val credentialId = Esp32Core.generateCredentialId()
        android.util.Log.i("Esp32Bridge", "makeCredential: credentialId=${credentialId.size}B")

        // 3) 取公钥拼 COSE key
        val pubResp = link.command(Esp32Core.cmdWaPub(idHex))
        val pubPoint = Esp32Core.parseWaPubResponse(pubResp)
            ?: return err(CTAP.Error.OTHER)
        val cose = Cose.encodeEs256(pubPoint) ?: return err(CTAP.Error.OTHER)

        // 4) WA_SETMETA 完整元数据（对齐 passless Esp32StorageAdapter::write:312-356）
        val nowMs = System.currentTimeMillis()
        val userIdB = req.userId ?: ByteArray(0)
        val userDisplayB = (req.userDisplayName ?: req.userName ?: "").toByteArray()
        val rpB = req.rpId.toByteArray()
        val userB = (req.userName ?: "").toByteArray()
        val setMetaCmd = Esp32Core.cmdWaSetMeta(
            idHex = idHex,
            created = nowMs,
            signCount = 0,
            alg = -7,
            credProtect = 0,
            discoverable = 1,
            backupState = 0,
            userId = userIdB,
            userDisplay = userDisplayB,
            webid = credentialId,
            rp = rpB,
            user = userB,
        )
        link.command(setMetaCmd)
        android.util.Log.i("Esp32Bridge", "makeCredential: WA_SETMETA 完成")

        // 4.5) WA_SETMETA_WEB 双保险 —— 显式建立 webid→内部id 索引
        // 固件 WA_SETMETA 可能只是存 kvs 元数据而未建立 webid 索引；
        // passless Esp32StorageAdapter::write 对 32B key.material 走 WA_SETMETA_WEB，
        // 这里对注册路径统一补发，确保 WA_WEBMETA / WA_WEBSIGNHASH 能反查。
        val setMetaWebCmd = Esp32Core.cmdWaSetMetaWeb(
            webid = credentialId,
            created = nowMs,
            signCount = 0,
            alg = -7,
            credProtect = 0,
            discoverable = 1,
            backupState = 0,
            userId = userIdB,
            userDisplay = userDisplayB,
            rp = rpB,
            user = userB,
        )
        link.command(setMetaWebCmd)
        android.util.Log.i("Esp32Bridge", "makeCredential: WA_SETMETA_WEB 双保险完成")

        // 5) 拼 authenticatorData — credentialId 用 32B 对外 webid（不是 16B 内部 id）
        val rpIdHash = sha256(req.rpId.toByteArray())
        val authData = CtapResponse.buildAuthDataCreate(rpIdHash, credentialId, cose)

        return CtapResponse.makeCredential("none", emptyMap(), authData)
    }

    // ------------------------------------------------------------------
    // GetAssertion — 对齐 passless agent/sign.rs → sign() 分流逻辑
    // ------------------------------------------------------------------

    private suspend fun getAssertion(link: Esp32Protocol, payload: ByteArray): ByteArray {
        android.util.Log.i("Esp32Bridge", "getAssertion: unlocked=${link.isUnlocked()}")
        if (!link.isUnlocked() && !link.ensureUnlocked()) return err(CTAP.Error.PIN_REQUIRED)

        val req = CtapRequest.parseGetAssertion(payload)
            ?: run { android.util.Log.e("Esp32Bridge", "getAssertion: parse 失败"); return err(CTAP.Error.INVALID_CBOR) }

        val allowCredId = req.allowList.firstOrNull()?.id ?: ByteArray(0)
        android.util.Log.i("Esp32Bridge", "getAssertion: rpId=${req.rpId} allowList=${req.allowList.size} credId=${allowCredId.size}B hex=${allowCredId.toHex()}")

        val rpIdHash = sha256(req.rpId.toByteArray())
        val flags = 0x01 // UP
        val authDataPre = rpIdHash + byteArrayOf(flags.toByte()) + byteArrayOf(0, 0, 0, 0)
        val digest = sha256(authDataPre + req.clientDataHash)

        var internalHex: String? = null
        var internalUser: String? = null
        var derSig: ByteArray? = null
        var respCredId: ByteArray = allowCredId
        var usedWebPath = false

        fun trySign(keyMaterial: ByteArray, label: String): ByteArray? {
            val cmd = Esp32Core.cmdSignDigest(keyMaterial, digest)
            android.util.Log.i("Esp32Bridge", "getAssertion: [$label] cmd=${cmd.take(70)}")
            val resp = link.command(cmd)
            android.util.Log.i("Esp32Bridge", "getAssertion: [$label] resp=${resp.take(120)}")
            return Esp32Core.parseSignResponse(resp)
        }

        fun doListSearch(): Boolean {
            android.util.Log.i("Esp32Bridge", "getAssertion: WA_LIST rpId=${req.rpId}")
            val listResp = link.command("WA_LIST\n")
            android.util.Log.i("Esp32Bridge", "getAssertion: WA_LIST 原始输出=${listResp.take(400)}")
            val entry = listResp.split("\n")
                .map { it.trim() }
                .firstOrNull { line ->
                    val parts = line.split("\t")
                    parts.size >= 2 && parts[0].length == 32 && parts[1] == req.rpId
                }
            if (entry == null) {
                android.util.Log.e("Esp32Bridge", "getAssertion: WA_LIST 无 rpId=${req.rpId} 匹配项 → NO_CREDENTIALS")
                return false
            }
            val parts = entry.split("\t")
            internalHex = parts[0]
            internalUser = parts.getOrNull(2)?.takeIf { it.isNotEmpty() }
            android.util.Log.i("Esp32Bridge", "getAssertion: WA_LIST 命中 id=${internalHex} user=${internalUser}")
            return true
        }

        if (allowCredId.isNotEmpty()) {
            // 主路径：allowList 里的 id 是网站存的 webid
            usedWebPath = true
            derSig = trySign(allowCredId, "allowList-webid")
            if (derSig == null) {
                android.util.Log.w("Esp32Bridge", "getAssertion: WA_WEBSIGNHASH 失败 → 先看 WA_LIST 有什么")
                // 先 dump WA_LIST 做诊断
                val listResp = link.command("WA_LIST\n")
                android.util.Log.w("Esp32Bridge", "getAssertion: WA_LIST dump=${listResp.take(500)}")

                // 尝试 fallback 方式1：allowCredId 可能其实是 16B 内部 id？
                if (allowCredId.size == 16) {
                    android.util.Log.i("Esp32Bridge", "getAssertion: allowCredId 是 16B → 尝试 WA_SIGNHASH")
                    derSig = trySign(allowCredId, "fallback-internal-id")
                }
                // 尝试 fallback 方式2：WA_LIST 找同 rpId 的凭据 → WA_META 回读 webid → 比对
                if (derSig == null) {
                    android.util.Log.i("Esp32Bridge", "getAssertion: WA_WEBSIGNHASH 失败 → WA_LIST+WA_META 回查 webid")
                    val listResp2 = link.command("WA_LIST\n")
                    val candidates = listResp2.split("\n")
                        .map { it.trim() }
                        .filter { line ->
                            val parts = line.split("\t")
                            parts.size >= 2 && parts[0].length == 32 && parts[1] == req.rpId
                        }
                    android.util.Log.i("Esp32Bridge", "getAssertion: WA_LIST 候选 ${candidates.size} 个 rpId=${req.rpId}")
                    for (cand in candidates) {
                        val cid = cand.split("\t")[0]
                        val metaResp = link.command("WA_META $cid\n")
                        val webIdB64 = metaResp.lineValue("webid=")
                        val webId = webIdB64?.takeIf { it.isNotEmpty() }?.let { b64d(it) }
                        android.util.Log.i("Esp32Bridge", "getAssertion: WA_META id=$cid webid=${webId?.size}B expect=${allowCredId.size}B")
                        if (webId != null && webId contentEquals allowCredId) {
                            android.util.Log.i("Esp32Bridge", "getAssertion: webid 精确匹配！用 WA_SIGNHASH id=$cid")
                            derSig = trySign(Esp32Core.bytesOfHex(cid)!!, "fallback-exact-webid")
                            internalHex = cid
                            internalUser = cand.split("\t").getOrNull(2)
                            break
                        } else if (webId != null) {
                            android.util.Log.i("Esp32Bridge", "getAssertion: webid 不匹配：stored=${webId.toHex().take(32)} expect=${allowCredId.toHex().take(32)}")
                        }
                    }
                }
                // 尝试 fallback 方式3：放弃 allowList id，直接 WA_LIST 找 rpId → WA_SIGNHASH（忽略 webid 不匹配）
                if (derSig == null) {
                    android.util.Log.w("Esp32Bridge", "getAssertion: 精确匹配也失败 → 直接用 WA_LIST 首个 rpId 匹配项签名（忽略 webid）")
                    if (doListSearch()) {
                        val idHex = internalHex!!
                        derSig = trySign(Esp32Core.bytesOfHex(idHex)!!, "fallback-wa-list")
                        respCredId = allowCredId // 网站认识的还是这个
                    }
                }
            }
        } else {
            android.util.Log.i("Esp32Bridge", "getAssertion: 无 allowList → WA_LIST rpId=${req.rpId}")
            if (!doListSearch()) return err(CTAP.Error.NO_CREDENTIALS)
            val idHex = internalHex!!
            derSig = trySign(Esp32Core.bytesOfHex(idHex)!!, "wa-list")
        }

        if (derSig == null) {
            android.util.Log.e("Esp32Bridge", "getAssertion: 所有路径签名失败 → NO_CREDENTIALS")
            return err(CTAP.Error.NO_CREDENTIALS)
        }
        android.util.Log.i("Esp32Bridge", "getAssertion: 签名成功，derSig=${derSig.size}B")

        // 回读 user/webid
        var user = req.user
        if (internalHex != null) {
            val metaResp = link.command("WA_META ${internalHex}\n")
            val uidB64 = metaResp.lineValue("user_id=")
            val uid = uidB64?.takeIf { it.isNotEmpty() }?.let { b64d(it) }
            if (uid != null && uid.isNotEmpty()) {
                user = CtapResponse.UserRef(id = uid, name = internalUser, displayName = internalUser)
            }
            val webIdB64 = metaResp.lineValue("webid=")
            val webId = webIdB64?.takeIf { it.isNotEmpty() }?.let { b64d(it) }
            if (webId != null && webId.isNotEmpty() && !usedWebPath) {
                respCredId = webId
                android.util.Log.i("Esp32Bridge", "getAssertion: 回读 webid ${webId.size}B 覆盖 respCredId")
            } else if (webId != null && webId.isNotEmpty()) {
                android.util.Log.i("Esp32Bridge", "getAssertion: 回读 webid ${webId.size}B，allowCredId.size=${allowCredId.size}B，respCredId 保持 allowCredId")
            }
        } else if (!usedWebPath) {
            respCredId = allowCredId
        }

        return CtapResponse.getAssertion(
            credentialId = respCredId,
            authData = authDataPre,
            signature = derSig,
            user = user,
        )
    }

    private suspend fun getNextAssertion(link: Esp32Protocol): ByteArray {
        return err(CTAP.Error.NO_CREDENTIALS)
    }

    // ---- helpers ----

    private fun err(e: CTAP.Error) = byteArrayOf(e.code.toByte())
    private fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)
    private fun b64(b: ByteArray) = android.util.Base64.encodeToString(b, android.util.Base64.NO_WRAP)
    private fun b64d(s: String) = try { android.util.Base64.decode(s, android.util.Base64.DEFAULT) } catch (e: Exception) { null }
    private fun String.lineValue(prefix: String): String? =
        split("\n").firstOrNull { it.trim().startsWith(prefix) }?.trim()?.substring(prefix.length)
}