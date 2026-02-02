package com.echworkers.android.model

import kotlinx.serialization.Serializable

@Serializable
enum class ProxyMode {
    GLOBAL,
    BYPASS,
    PROXY_ONLY;
    
    fun displayName(): String = when (this) {
        GLOBAL -> "全局代理"
        BYPASS -> "绕过模式"
        PROXY_ONLY -> "仅代理"
    }
    
    fun description(): String = when (this) {
        GLOBAL -> "所有应用流量通过 VPN"
        BYPASS -> "勾选的应用不代理，其他代理"
        PROXY_ONLY -> "仅勾选的应用代理"
    }
}

@Serializable
data class ProxyConfig(
    val mode: ProxyMode = ProxyMode.GLOBAL,
    val selectedPackages: Set<String> = emptySet()
) {
    fun shouldProxy(packageName: String): Boolean {
        return when (mode) {
            ProxyMode.GLOBAL -> true
            ProxyMode.BYPASS -> packageName !in selectedPackages
            ProxyMode.PROXY_ONLY -> packageName in selectedPackages
        }
    }
}
