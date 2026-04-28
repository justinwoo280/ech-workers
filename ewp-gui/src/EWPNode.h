#pragma once

#include <QString>
#include <QJsonObject>

// EWP v2 node configuration.
//
// Removed from v1: appProtocol/Trojan, password, userAgent,
// contentType, xhttpMode, enableTLS, minTLSVersion, echDomain,
// dnsServer, enablePQC, enableFlow, useMozillaCA. v2 mandates
// EWP + TLS 1.3 + ML-KEM-768 + Mozilla CA bundle, with no UI
// surface to weaken any of those.
//
// JSON deserialisation tolerates leftover v1 keys silently
// (we just ignore them), but produces only the v2 set.
struct EWPNode {
    int id = -1;
    QString name;

    QString server;            // TCP host or IP — UI label "服务器地址"
    int serverPort = 443;
    QString host;              // HTTP Host / gRPC :authority. Empty -> derived from server.

    QString uuid;              // 32 hex chars

    enum TransportMode { WS = 0, GRPC = 1, XHTTP = 2, H3GRPC = 3 };
    TransportMode transportMode = WS;

    QString wsPath          = "/ewp";
    QString grpcServiceName = "ProxyService";
    QString xhttpPath       = "/xhttp";

    QString sni;               // Empty -> derived from host -> server

    bool enableECH = true;
    /**
     * Domain that publishes the ECH public key (HTTPS DNS RR). Distinct
     * from sni — sni is the backend's real name (encrypted by ECH),
     * echDomain is the *public* domain hosting the ECH config.
     *
     * Centralised ECH services like Cloudflare keep the key under
     * "cloudflare-ech.com" while the customer's backend SNI is some
     * customer-specific domain. We do NOT auto-derive echDomain from
     * sni: an HTTPS RR lookup of the backend usually returns no ECH
     * config, and the bootstrap would silently fall back to plain TLS.
     * Empty here ⇒ fall back to sni (only correct for self-hosted ECH).
     */
    QString echDomain;
    QString dohServers;        // Optional CSV; empty -> built-in default (AliDNS + DNSPod)

    int latency = 0;           // ms; 0 = untested, -1 = failed

    // -------- serialisation --------

    QJsonObject toJson() const {
        QJsonObject o;
        o["id"]              = id;
        o["name"]            = name;
        o["server"]          = server;
        o["serverPort"]      = serverPort;
        o["host"]            = host;
        o["uuid"]            = uuid;
        o["transportMode"]   = static_cast<int>(transportMode);
        o["wsPath"]          = wsPath;
        o["grpcServiceName"] = grpcServiceName;
        o["xhttpPath"]       = xhttpPath;
        o["sni"]             = sni;
        o["enableECH"]       = enableECH;
        if (!echDomain.isEmpty()) o["echDomain"] = echDomain;
        o["dohServers"]      = dohServers;
        return o;
    }

    static EWPNode fromJson(const QJsonObject &obj) {
        EWPNode n;
        n.id              = obj["id"].toInt(-1);
        n.name            = obj["name"].toString();
        n.serverPort      = obj["serverPort"].toInt(443);
        n.uuid            = obj["uuid"].toString();
        n.transportMode   = static_cast<TransportMode>(obj["transportMode"].toInt(0));
        n.wsPath          = obj["wsPath"].toString("/ewp");
        n.grpcServiceName = obj["grpcServiceName"].toString("ProxyService");
        n.xhttpPath       = obj["xhttpPath"].toString("/xhttp");
        n.sni             = obj["sni"].toString();
        n.enableECH       = obj["enableECH"].toBool(true);
        n.echDomain       = obj["echDomain"].toString();
        n.dohServers      = obj["dohServers"].toString();
        n.server          = obj["server"].toString();
        n.host            = obj["host"].toString();
        // v1 callers used to put the connect target in serverIP/serverAddress —
        // we do not migrate those any more; users will re-create nodes.
        return n;
    }

    // -------- presentation --------

    QString displayType() const {
        switch (transportMode) {
            case WS:     return "EWP-WS";
            case GRPC:   return "EWP-gRPC";
            case XHTTP:  return "EWP-XHTTP";
            case H3GRPC: return "EWP-H3";
        }
        return "EWP";
    }

    QString displayAddress() const {
        return QString("%1:%2").arg(server).arg(serverPort);
    }

    QString displayLatency() const {
        if (latency < 0) return "失败";
        if (latency == 0) return "-";
        return QString("%1 ms").arg(latency);
    }

    bool isValid() const {
        return !server.isEmpty() && !uuid.isEmpty();
    }

    QString displayAuth() const {
        return uuid.left(8) + "...";
    }

    // Effective TLS SNI: sni -> host -> server.
    QString effectiveSNI() const {
        if (!sni.isEmpty())  return sni;
        if (!host.isEmpty()) return host;
        return server;
    }
};
