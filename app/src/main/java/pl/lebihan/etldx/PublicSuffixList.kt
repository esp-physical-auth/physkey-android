package pl.lebihan.etldx

import java.io.InputStream

/**
 * 本地精简版 Public Suffix List（替代 jitpack 上的 com.github.mimi89999:etldx）。
 *
 * 离线编译环境下该三方库未缓存，这里实现一个等价的最小 API，供 Authnkey 做
 * eTLD+1 排序使用：
 *   - [split] 返回域名拆解结果（含 registrableDomain / subdomain / name）
 *   - 解析 public_suffix_list.dat（PSL 规则：普通规则 + 通配符 * + 例外 !）
 *
 * 注意：这是**降级实现**，规则匹配为简化版（精确 + 通配一层），
 * 足以满足"把同 registrable domain 归到一起排序"的需求。
 */
class InvalidDomainNameException(message: String) : Exception(message)

data class DomainName(
    val name: String,
    val registrableDomain: String?,
    val subdomain: String?,
)

class PublicSuffixList(input: InputStream) {

    // 规则集：普通规则存 "com", "co.uk"；通配规则存 "*.ck"；例外存 "!www.ck"
    private val exact = HashSet<String>()
    private val wildcard = HashSet<String>()
    private val exception = HashSet<String>()

    init {
        input.bufferedReader(Charsets.UTF_8).useLines { lines ->
            for (raw in lines) {
                val line = raw.trim()
                if (line.isEmpty() || line.startsWith("//")) continue
                when {
                    line.startsWith("!") -> exception.add(line.substring(1).lowercase())
                    line.startsWith("*.") -> wildcard.add(line.substring(2).lowercase())
                    else -> exact.add(line.lowercase())
                }
            }
        }
    }

    /** 拆解域名，返回 name / registrableDomain(eTLD+1) / subdomain。 */
    fun split(domain: String): DomainName {
        val d = domain.trim().lowercase().trimEnd('.')
        if (d.isEmpty() || !d.contains('.') && !isKnownTld(d)) {
            throw InvalidDomainNameException("not a domain: $domain")
        }
        val labels = d.split('.')

        // 找出 public suffix 长度（从右往左）
        val suffixLen = publicSuffixLength(labels)
        return if (suffixLen >= labels.size) {
            // 域名本身就是 public suffix（如 "com" 或 "co.uk"）
            DomainName(name = d, registrableDomain = null, subdomain = null)
        } else {
            val reg = labels.subList(labels.size - suffixLen - 1, labels.size).joinToString(".")
            val sub = if (labels.size - suffixLen - 1 > 0) {
                labels.subList(0, labels.size - suffixLen - 1).joinToString(".")
            } else null
            DomainName(name = d, registrableDomain = reg, subdomain = sub)
        }
    }

    private fun isKnownTld(t: String): Boolean = exact.contains(t) || wildcard.contains(t)

    /** 返回 public suffix 的标签数。默认规则：单标签。 */
    private fun publicSuffixLength(labels: List<String>): Int {
        // 例外优先：!www.ck → public suffix 为 "ck"（长度按例外去掉最左标签）
        for (len in labels.size downTo 1) {
            val candidate = labels.subList(labels.size - len, labels.size).joinToString(".")
            if (exception.contains(candidate)) {
                // 例外的后缀部分 = candidate 去掉最左一个标签
                return len - 1
            }
        }
        // 通配：*.ck 表示 "任意.ck" 都是 public suffix（长度 2）
        for (len in labels.size downTo 1) {
            val candidate = labels.subList(labels.size - len, labels.size).joinToString(".")
            if (wildcard.contains(candidate)) {
                // 匹配到通配基准，至少加一层
                return (len + 1).coerceAtMost(labels.size)
            }
        }
        // 精确规则：取最长的精确匹配
        for (len in labels.size downTo 1) {
            val candidate = labels.subList(labels.size - len, labels.size).joinToString(".")
            if (exact.contains(candidate)) return len
        }
        // 未知 TLD：按单标签处理
        return 1
    }
}
