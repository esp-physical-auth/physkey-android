package pl.lebihan.authnkey

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Base64
import android.util.Log
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.security.SecureRandom
import java.util.ArrayDeque
import java.util.UUID
import kotlin.coroutines.resume

/**
 * ESP32 后端 NUS 文本协议客户端（对齐 physkey-linux/cmd/passless/src/esp32.rs 的 BleLink）。
 *
 * 职责：
 *  - BLE 扫描/连接（设备名可配置，见 Esp32Config）/ 订阅 NUS TX 通知
 *  - 命令分帧发送（4 位 hex 长度前缀 + 20B 分片，不在 UTF-8 多字节处切开）
 *  - 响应累积切行 + “终止行后静默 500ms 收敛”
 *  - CA 信任链校验（GETCERT 验签 + AUTH 挑战响应）
 *  - 解锁状态机（HASPASS / AUTHPASS，断连即失效）
 */
class Esp32Protocol private constructor(
    private val context: Context,
    private val gatt: BluetoothGatt,
    private val rx: BluetoothGattCharacteristic,
    private val tx: BluetoothGattCharacteristic,
    private var devicePub: ByteArray,
) {

    private val TAG = "Esp32Protocol"
    private val cmdLock = Mutex()

    @Volatile private var connected = true
    @Volatile private var unlocked = false

    /** 解锁密码回调（UI 弹窗）；未设置时无法自动解锁。 */
    @Volatile private var unlockPrompt: (suspend () -> String?)? = null

    // 通知累积缓冲
    private val lineQueue = ArrayDeque<String>()
    private val tail = StringBuilder()
    private val notifySignal = CompletableDeferred<Unit>().let { it }  // 占位，见 signalNotify
    @Volatile private var lastLineMs = 0L

    private val signal = object {
        @Volatile var waiter: CompletableDeferred<Unit>? = null
    }

    private fun signalNotify() {
        signal.waiter?.complete(Unit)
    }

    // ------------------------------------------------------------------
    // 连接与信任链
    // ------------------------------------------------------------------

    /** 扫描到的 BLE 设备（供 UI 选择）。作为类直接嵌套类，外部用 Esp32Protocol.ScanHit 引用。 */
    data class ScanHit(val name: String, val address: String)

    companion object {
        private const val TAG = "Esp32Protocol"

        /** 扫描并连接匹配的设备，完成 CA 信任链校验后返回。 */
        data class Verified(
            val protocol: Esp32Protocol,
            val deploymentId: String,
        )

        /** 扫描并连接匹配的设备，完成 CA 信任链校验后返回。 */
        suspend fun connect(context: Context): Esp32Protocol = connectVerified(context).protocol

        /**
         * 扫描周边 BLE 设备（去重），返回列表供用户选择。
         *
         * 不过滤名称（某些设备广播包里名称为空，比如 ESP32 可能只在下一次广播才带名字），
         * 把扫到的全部有名字/无名字设备都列出，由用户在弹窗里自行辨认。
         * @param windowMs 扫描时长
         */
        suspend fun scanDevices(
            context: Context,
            windowMs: Long = 12000L,
        ): List<ScanHit> = withContext(Dispatchers.IO) {
            requireBle(context)
            val mgr = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
            val adapter = mgr.adapter ?: throw AuthnkeyError.ConnectionFailed()
            val scanner = adapter.bluetoothLeScanner ?: throw AuthnkeyError.ConnectionFailed()
            Log.i(TAG, "scanDevices: 开始扫描（窗口 ${windowMs}ms）")

            val found = LinkedHashMap<String, ScanHit>()
            val seenAny = java.util.concurrent.atomic.AtomicInteger(0)
            val cb = object : ScanCallback() {
                override fun onScanResult(callbackType: Int, result: ScanResult) {
                    seenAny.incrementAndGet()
                    val name = try { result.device.name } catch (_: SecurityException) { null }
                    Log.d(TAG, "  扫到: ${result.device.address} name='$name' rssi=${result.rssi}")
                    // 保留有名字的；无名设备也保留（显示为未知），避免因广播缺名而漏掉 ESP32。
                    val prev = found[result.device.address]
                    if (prev == null || (prev.name.isBlank() && !name.isNullOrBlank())) {
                        found[result.device.address] = ScanHit(name ?: "", result.device.address)
                    }
                }
                override fun onBatchScanResults(results: MutableList<ScanResult>) {
                    for (r in results) onScanResult(ScanSettings.CALLBACK_TYPE_ALL_MATCHES, r)
                }
                override fun onScanFailed(errorCode: Int) { Log.w(TAG, "扫描失败: code=$errorCode") }
            }
            val settings = ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
                .setReportDelay(0L)
                .build()
            try {
                scanner.startScan(null, settings, cb)
            } catch (e: Exception) {
                Log.e(TAG, "startScan 异常: ${e.message}", e)
                throw AuthnkeyError.ConnectionFailed()
            }
            try {
                delay(windowMs)
            } finally {
                try { scanner.stopScan(cb) } catch (_: Exception) {}
            }
            Log.i(TAG, "scanDevices: 结束，共收到 ${seenAny.get()} 条广播，设备 ${found.size} 个")
            found.values.toList()
        }

        /**
         * 扫描并连接，完成 CA 信任链校验，并返回解析出的部署标识（供 UI 弹窗展示）。
         * 若 [address] 非空则直接连该地址（用户从列表选定）；否则自动扫描匹配首个设备。
         * 信任链（SSL/TLS 式三级链，全程离线，仅用内置根 CA 公钥）：
         *   根CA公钥 → 验中间CA证书 → 取中间CA公钥 → 验设备证书 → 取设备公钥 → 验 AUTH 响应
         */
        suspend fun connectVerified(context: Context, address: String? = null): Verified = withContext(Dispatchers.IO) {
            requireBle(context)
            val mgr = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
            val adapter = mgr.adapter ?: throw AuthnkeyError.ConnectionFailed()

            val target = address ?: (scanForDevice(context, adapter)
                ?: throw AuthnkeyError.ConnectionFailed())

            val device = adapter.getRemoteDevice(target)
            val gatt = withTimeout(Esp32Config.SCAN_TIMEOUT_MS) {
                device.connectGattSync(context)
            } ?: throw AuthnkeyError.ConnectionFailed()

            val svc = gatt.getService(UUID.fromString(Esp32Config.NUS_SERVICE_UUID))
                ?: throw AuthnkeyError.ConnectionFailed()
            val rx = svc.getCharacteristic(UUID.fromString(Esp32Config.NUS_RX_UUID))
                ?: throw AuthnkeyError.ConnectionFailed()
            val tx = svc.getCharacteristic(UUID.fromString(Esp32Config.NUS_TX_UUID))
                ?: throw AuthnkeyError.ConnectionFailed()

            // 开启通知
            gatt.setCharacteristicNotification(tx, true)
            val cccd = tx.getDescriptor(UUID.fromString(Esp32Config.NUS_CCCD_UUID))
            if (cccd != null) {
                cccd.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                gatt.writeDescriptor(cccd)
            }

            // 临时实例：用于信任链握手
            val link = Esp32Protocol(context, gatt, rx, tx, ByteArray(0))
            // ★ 把通知转发接到刚创建的 link 上（必须在建 link 之后）
            pendingNotify = { bytes -> link.onNotifyValue(bytes) }

            // ---- CA 信任链校验（对齐 physkey-dashboard/passless）----
            val certResp = link.command("GETCERT\n")
            Log.i(TAG, "connectVerified: GETCERT 响应=${certResp.take(40)} (${certResp.length}B)")
            val chainB64 = certResp.split("CERT:").getOrNull(1)?.trim()
                ?: throw AuthnkeyError.ConnectionFailed()
            // 必须先按 '|' 拆段再逐段 base64 解码（不能整串解码，否则 '|' 报错）
            val chainParts = chainB64.split('|').filter { it.isNotBlank() }
            val certDer = Base64.decode(chainParts[0], Base64.DEFAULT)
            val ucaDer = if (chainParts.size >= 2) Base64.decode(chainParts[1], Base64.DEFAULT) else null
            Log.i(TAG, "connectVerified: 设备证书 DER=${certDer.size}B，中间CA证书=${ucaDer?.size ?: 0}B，开始验签…")
            val cert = if (ucaDer != null) {
                Esp32Ca.verifyChain(Esp32Config.caPubkeyBytes(context), certDer, ucaDer)
            } else {
                Esp32Ca.verifyCert(Esp32Config.caPubkeyBytes(context), certDer)
            }
            Log.i(TAG, "connectVerified: 验签通过，部署标识='${cert.deploymentId}'")

            val nonce = ByteArray(32).also { SecureRandom().nextBytes(it) }
            val nonceB64 = Base64.encodeToString(nonce, Base64.NO_WRAP)
            Log.i(TAG, "connectVerified: 发送 AUTH 挑战…")
            val authResp = link.command("AUTH $nonceB64\n")
            Log.i(TAG, "connectVerified: AUTH 响应=${authResp.take(40)}")
            val sigB64 = authResp.split("SIG:").getOrNull(1)?.trim()
                ?: throw AuthnkeyError.ConnectionFailed()
            val sig = Base64.decode(sigB64, Base64.DEFAULT)
            if (!Esp32Ca.verifyChallenge(cert.devicePub, nonce, sig)) {
                throw SecurityException("挑战响应验签失败：设备可能未持有对应私钥")
            }
            Log.i(TAG, "CA 信任链校验通过，部署标识='${cert.deploymentId}'")

            // ★ 复用握手用的同一个实例：pendingNotify 指向它。
            //   之前这里新建了第二个 Esp32Protocol 返回，通知仍路由到旧实例，
            //   导致连接后所有命令收不到响应（超时空串），AUTHPASS 永远失败，
            //   每条 CTAP 命令都触发 ensureUnlocked() → 反复弹密码框。
            link.setDevicePub(cert.devicePub)
            Verified(link, cert.deploymentId)
        }

        /**
         * 信任链验签（SSL/TLS 式三级链，全程离线，仅用内置根 CA 公钥）：
         *   证书串（GETCERT 返回）可能是：
         *     - 两段链：“设备证书|中间CA证书” → 根CA公钥→验中间CA证书→验设备证书
         *     - 单段：“设备证书”（旧模式）    → 直接用内置根 CA 公钥验
         * 返回设备证书信息（含 deployment_id）。
         */
        private suspend fun resolveCaAndVerify(
            context: Context,
            certPayload: ByteArray,
        ): Esp32Ca.DeviceCert {
            // 解析是否两段链（用 0x7c '|' 分隔）
            val parts = splitCertChain(certPayload)
            val rootPub = Esp32Config.caPubkeyBytes(context)
            if (parts.size == 2) {
                // 三级链：根CA公钥验中间CA证书，再验设备证书
                return Esp32Ca.verifyChain(rootPub, parts[0], parts[1])
            }
            // 单段：直接用内置根 CA 公钥验设备证书
            return Esp32Ca.verifyCert(rootPub, parts[0])
        }

        /** 把 GETCERT 返回的字节串按 '|' 拆成 1 或 2 段证书。 */
        private fun splitCertChain(data: ByteArray): List<ByteArray> {
            val out = mutableListOf<ByteArray>()
            var start = 0
            for (i in data.indices) {
                if (data[i] == '|'.code.toByte()) {
                    out.add(data.copyOfRange(start, i))
                    start = i + 1
                }
            }
            out.add(data.copyOfRange(start, data.size))
            return out.filter { it.isNotEmpty() }
        }

        private fun requireBle(context: Context) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                if (ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_CONNECT)
                    != PackageManager.PERMISSION_GRANTED
                ) throw AuthnkeyError.ConnectionFailed()
            }
        }

        private suspend fun scanForDevice(context: Context, adapter: BluetoothAdapter): String? =
            suspendCancellableCoroutine { cont ->
                val scanner = adapter.bluetoothLeScanner ?: run { cont.resume(null); return@suspendCancellableCoroutine }
                val cb = object : ScanCallback() {
                    override fun onScanResult(callbackType: Int, result: ScanResult) {
                        val name = result.device.name
                        if (Esp32Config.matches(context, name)) {
                            try { scanner.stopScan(this) } catch (_: Exception) {}
                            cont.resume(result.device.address)
                        }
                    }
                    override fun onScanFailed(errorCode: Int) { cont.resume(null) }
                }
                val settings = ScanSettings.Builder()
                    .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                    .build()
                scanner.startScan(null, settings, cb)
                cont.invokeOnCancellation { try { scanner.stopScan(cb) } catch (_: Exception) {} }
            }

        private suspend fun android.bluetooth.BluetoothDevice.connectGattSync(
            context: Context,
        ): BluetoothGatt? = suspendCancellableCoroutine { cont ->
            val cb = object : BluetoothGattCallback() {
                private var done = false
                override fun onConnectionStateChange(g: BluetoothGatt, status: Int, newState: Int) {
                    if (newState == BluetoothProfile.STATE_CONNECTED) {
                        g.discoverServices()
                    } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                        if (!done) { done = true; cont.resume(null) }
                    }
                }
                override fun onServicesDiscovered(g: BluetoothGatt, status: Int) {
                    if (done) return
                    done = true
                    cont.resume(g)
                }
                // ★ 关键：把 NUS TX 通知转发给 Esp32Protocol（否则命令永远收不到响应）
                override fun onCharacteristicChanged(
                    g: BluetoothGatt,
                    characteristic: BluetoothGattCharacteristic,
                    value: ByteArray,
                ) {
                    pendingNotify?.invoke(value)
                }
                @Deprecated("deprecated")
                override fun onCharacteristicChanged(
                    g: BluetoothGatt,
                    characteristic: BluetoothGattCharacteristic,
                ) {
                    val v = characteristic.value ?: return
                    pendingNotify?.invoke(v)
                }
            }
            val g = connectGatt(context, false, cb)
            if (g == null) cont.resume(null)
        }

        /** 通知转发目标（由 connectVerified 在创建 Esp32Protocol 后赋值）。 */
        @Volatile
        private var pendingNotify: ((ByteArray) -> Unit)? = null
    }

    // ------------------------------------------------------------------
    // 解锁
    // ------------------------------------------------------------------

    /** 查询设备是否已设置口令。返回 "pass set" / "no pass" / null。 */
    suspend fun hasPass(): Boolean? {
        val r = command("HASPASS\n")
        return when {
            r.contains("pass set") -> true
            r.contains("no pass") -> false
            else -> null
        }
    }

    /** 用口令解锁（AUTHPASS）。成功返回 true 并缓存解锁状态。 */
    suspend fun unlock(password: String): Boolean {
        val r = command("AUTHPASS $password\n")
        val ok = r.startsWith("OK")
        unlocked = ok
        return ok
    }

    fun isUnlocked() = unlocked

    /** 信任链校验完成后回填设备公钥（握手期实例未知公钥，见 connectVerified）。 */
    fun setDevicePub(pub: ByteArray) {
        devicePub = pub
    }

    /**
     * 确保设备已解锁（参考 passless 的 ensure_unlocked）：
     *   - 已解锁 → 直接返回；
     *   - 未解锁且提供了回调 → 弹窗取密码 → AUTHPASS 解锁；
     *   - 未解锁且无回调 → 返回 false。
     * 成功返回 true。
     */
    suspend fun ensureUnlocked(): Boolean {
        if (unlocked) return true
        val pw = unlockPrompt?.invoke() ?: return false
        if (pw.isEmpty()) return false
        return unlock(pw)
    }

    /** 设置解锁密码回调（由 UI 弹窗提供）。 */
    fun setUnlockPrompt(prompt: (suspend () -> String?)?) {
        unlockPrompt = prompt
    }

    // ------------------------------------------------------------------
    // 命令收发
    // ------------------------------------------------------------------

    /**
     * 发送一条文本命令并返回完整响应（多行用 '\n' 连接）。
     * 自动处理分帧与响应收敛；若设备报 "ERR locked" 相关错误则清除解锁缓存。
     */
    suspend fun command(cmd: String): String = cmdLock.withLock {
        if (!connected) throw AuthnkeyError.NotConnected()

        sendFramed(cmd)

        // 响应收敛：以“静默窗口”为准。
        // 设备响应为 `OK ...\n` / `ERR ...\n`，但长响应（如 GETCERT 证书链）
        // 分片到达后，不能保证一定收得到尾部 `\n`；因此改成：
        //   收到以 OK/ERR 开头的内容，且后续静默一个窗口 → 认为响应结束。
        val deadline = System.currentTimeMillis() + Esp32Config.COMMAND_TIMEOUT_MS
        var full = ""

        withContext(Dispatchers.IO) {
            while (true) {
                if (System.currentTimeMillis() > deadline) {
                    // 超时：若已有部分内容则返回；否则返回空串（不再抛异常崩进程）
                    if (full.isNotBlank()) {
                        Log.w(TAG, "command 超时：已有部分响应(${full.length}B)，按已收内容返回")
                        return@withContext
                    }
                    Log.w(TAG, "command 超时且无任何响应（检查通知路由/CCCD/连接状态）")
                    // ★ 不抛 NotConnected（会崩 main），改由调用方根据空响应处理
                    return@withContext
                }
                // 取当前缓冲（不要求有换行）
                val chunk = synchronized(tail) {
                    val s = tail.toString()
                    if (s.isNotEmpty()) tail.setLength(0)
                    s
                }
                if (chunk.isNotEmpty()) {
                    full += chunk
                } else {
                    // 静默窗口内无新数据
                    val started = full.startsWith("OK") || full.startsWith("ERR")
                    val hasTerminal = full.contains("OK ") || full.contains("ERR ") ||
                        full.startsWith("OK") || full.startsWith("ERR")
                    if (hasTerminal) {
                        // 已收到终止响应且静默 → 结束
                        break
                    }
                }
                // 等待新数据（静默窗口）
                val d = CompletableDeferred<Unit>()
                signal.waiter = d
                try {
                    withTimeout(Esp32Config.QUIET_WINDOW_MS) { d.await() }
                } catch (_: TimeoutCancellationException) {
                    // 静默窗口到，进入下一轮判定
                } finally {
                    signal.waiter = null
                }
            }
        }

        val out = full.trim()
        Log.i(TAG, "command 返回(${out.length}B): ${out.take(80)}${if (out.length > 80) "..." else ""}")
        if (out.contains("ERR locked") || out.contains("engine locked") || out.contains("not unlocked")) {
            unlocked = false
        }
        return@withLock out
    }

    /** 若在 [timeoutMs] 内拿到一整行则返回，否则 null。 */
    private suspend fun pollLine(timeoutMs: Long): String? {
        val start = System.currentTimeMillis()
        while (System.currentTimeMillis() - start < timeoutMs) {
            synchronized(tail) {
                val idx = tail.indexOf("\n")
                if (idx >= 0) {
                    val line = tail.substring(0, idx).trim()
                    tail.delete(0, idx + 1)
                    if (line.isNotEmpty()) return line
                }
            }
            val d = CompletableDeferred<Unit>()
            signal.waiter = d
            try {
                withTimeout(timeoutMs - (System.currentTimeMillis() - start)) { d.await() }
            } catch (e: TimeoutCancellationException) {
                // 静默窗口到
            } finally {
                signal.waiter = null
            }
        }
        return null
    }

    private suspend fun sendFramed(cmd: String) = withContext(Dispatchers.IO) {
        val body = if (cmd.endsWith("\n")) cmd else "$cmd\n"
        val bodyBytes = body.toByteArray(Charsets.UTF_8)
        val lenHex = String.format("%04x", bodyBytes.size)
        val frame = (lenHex + body).toByteArray(Charsets.UTF_8)

        var i = 0
        while (i < frame.size) {
            var end = (i + Esp32Config.WRITE_CHUNK).coerceAtMost(frame.size)
            // 不在 UTF-8 多字节字符中间切开
            while (end > i && end < frame.size && (frame[end].toInt() and 0xC0) == 0x80) end--
            val chunk = frame.copyOfRange(i, end)

            var attempt = 0
            var ok = false
            while (attempt < 5 && !ok) {
                ok = writeChunk(chunk)
                if (!ok) { delay(60L * (attempt + 1)); attempt++ }
            }
            if (!ok) throw AuthnkeyError.NotConnected()

            i = end
            if (i < frame.size) delay(Esp32Config.CHUNK_DELAY_MS)
        }
    }

    private suspend fun writeChunk(chunk: ByteArray): Boolean =
        suspendCancellableCoroutine { cont ->
            val c = rx
            c.writeType = BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
            c.value = chunk
            val ok = gatt.writeCharacteristic(c)
            cont.resume(ok)
        }

    /** GATT 回调中调用：把通知字节追加到累积缓冲并唤醒等待者。 */
    fun onNotifyValue(value: ByteArray?) {
        if (value == null) return
        Log.d(TAG, "<< notify ${value.size}B: ${String(value, Charsets.UTF_8)}")
        synchronized(tail) { tail.append(String(value, Charsets.UTF_8)) }
        lastLineMs = System.currentTimeMillis()
        signalNotify()
    }

    fun onDisconnected() {
        connected = false
        unlocked = false
    }

    fun close() {
        connected = false
        unlocked = false
        try { gatt.disconnect(); gatt.close() } catch (_: Exception) {}
    }
}
