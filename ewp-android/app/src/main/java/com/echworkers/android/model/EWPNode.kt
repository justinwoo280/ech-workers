package com.echworkers.android.model

import kotlinx.serialization.Serializable
import java.util.UUID

/**
 * EWP v2 node configuration. Backward-incompatible with v1: trojan,
 * flow padding, PQC opt-in, TLS-version selection, xhttp stream-down,
 * userAgent / contentType injection — all gone. v2 mandates EWP +
 * TLS 1.3 + ML-KEM-768 + ECH always-on if available.
 *
 * Existing v1 node lists in app storage are NOT migrated. Users will
 * need to re-create their nodes; this is a deliberate trade-off in
 * exchange for not carrying v1's design mistakes forward.
 */
@Serializable
data class EWPNode(
    val id: String = UUID.randomUUID().toString(),
    val name: String,

    val serverAddress: String,
    val serverPort: Int = 443,

    /** EWP token; hex 32 chars (16 bytes). */
    val uuid: String = "",

    /** Outer transport selector. */
    val transportMode: TransportMode = TransportMode.WS,
    val wsPath: String = "/ewp",
    val grpcServiceName: String = "ProxyService",
    val xhttpPath: String = "/xhttp",

    /** HTTP Host header / gRPC :authority. Empty -> derive from serverAddress. */
    val host: String = "",
    /** TLS SNI. Empty -> derive from serverAddress (or fall back to host). */
    val sni: String = "",

    /** Encrypted ClientHello toggle. v2 strongly recommends keeping it on. */
    val enableECH: Boolean = true,

    /**
     * Domain whose HTTPS resource record carries the ECH config. Distinct from
     * SNI: SNI is the backend's real name (encrypted by ECH), echDomain is the
     * public domain that *publishes* the ECH key.
     *
     * The two are unrelated for centralised ECH services — Cloudflare, for
     * example, hosts ECH keys under "cloudflare-ech.com" while the actual
     * backend SNI is the customer's own domain. Empty here ⇒ ECH config will
     * be looked up against the SNI itself, which only works for self-hosted
     * ECH deployments. We do NOT auto-derive it from SNI/host because RFC
     * 9460 lookup of the backend domain typically returns no ECH config and
     * the bootstrap would silently fall back to plain TLS.
     */
    val echDomain: String = "",

    /** Optional override of the umbrella DoH list used by ewpmobile. Comma-separated. Empty -> built-in default (AliDNS + DNSPod). */
    val dohServers: String = "",

    val latency: Int = 0,
) {
    @Serializable
    enum class TransportMode { WS, GRPC, XHTTP, H3GRPC }

    fun isValid(): Boolean = serverAddress.isNotBlank() && uuid.isNotBlank()

    fun displayType(): String = "EWP-" + when (transportMode) {
        TransportMode.WS    -> "WS"
        TransportMode.GRPC  -> "gRPC"
        TransportMode.XHTTP -> "XHTTP"
        TransportMode.H3GRPC -> "H3"
    }

    fun displayAddress(): String = "$serverAddress:$serverPort"

    fun displayLatency(): String = when {
        latency < 0 -> "失败"
        latency == 0 -> "-"
        else -> "${latency}ms"
    }

    fun displayAuth(): String = if (uuid.length >= 8) "${uuid.take(8)}..." else "----"
}
