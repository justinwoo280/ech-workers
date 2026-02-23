#pragma once

#include <QString>
#include <QJsonObject>

// EWP 节点配置结构
struct EWPNode {
    int id = -1;
    QString name;

    // 连接目标：实际 TCP/UDP 连接的 IP 或域名（绕过 DNS 时填 IP）
    // UI 显示为"服务器地址"
    QString serverIP;
    int serverPort = 443;

    // HTTP Host 头 / CDN 路由域名（留空则同 serverIP）
    // UI 显示为"Host"（在传输配置中）
    QString serverAddress;

    // 应用层协议: 0=EWP, 1=Trojan
    enum AppProtocol { EWP = 0, TROJAN = 1 };
    AppProtocol appProtocol = EWP;

    // EWP 认证
    QString uuid;

    // Trojan 认证
    QString trojanPassword;

    // 传输协议: 0=WebSocket, 1=gRPC, 2=XHTTP, 3=H3gRPC
    enum TransportMode { WS = 0, GRPC = 1, XHTTP = 2, H3GRPC = 3 };
    TransportMode transportMode = WS;

    // WebSocket 配置
    QString wsPath = "/";

    // gRPC / H3gRPC 配置
    QString grpcServiceName = "ProxyService";
    QString userAgent;
    QString contentType;               // 仅 H3gRPC 有效

    // XHTTP 配置
    QString xhttpMode = "auto";
    QString xhttpPath = "/xhttp";

    // TLS 配置
    bool enableTLS = true;
    QString sni;                       // 留空则同 Host（serverAddress 或 serverIP）
    QString minTLSVersion = "1.2";     // "1.2" 或 "1.3"

    // ECH 配置
    bool enableECH = true;
    QString echDomain = "cloudflare-ech.com";
    QString dnsServer = "dns.alidns.com/dns-query";

    // PQC（独立于 ECH）
    bool enablePQC = false;

    // EWP 高级配置
    bool enableFlow = true;

    // 测试结果
    int latency = 0;  // ms, -1=失败, 0=未测试

    // 序列化
    QJsonObject toJson() const {
        QJsonObject obj;
        obj["id"] = id;
        obj["name"] = name;
        obj["serverIP"] = serverIP;
        obj["serverPort"] = serverPort;
        obj["serverAddress"] = serverAddress;
        obj["appProtocol"] = static_cast<int>(appProtocol);
        obj["uuid"] = uuid;
        obj["trojanPassword"] = trojanPassword;
        obj["transportMode"] = static_cast<int>(transportMode);
        obj["wsPath"] = wsPath;
        obj["grpcServiceName"] = grpcServiceName;
        obj["userAgent"] = userAgent;
        obj["contentType"] = contentType;
        obj["xhttpMode"] = xhttpMode;
        obj["xhttpPath"] = xhttpPath;
        obj["enableTLS"] = enableTLS;
        obj["sni"] = sni;
        obj["minTLSVersion"] = minTLSVersion;
        obj["enableECH"] = enableECH;
        obj["echDomain"] = echDomain;
        obj["dnsServer"] = dnsServer;
        obj["enablePQC"] = enablePQC;
        obj["enableFlow"] = enableFlow;
        return obj;
    }

    static EWPNode fromJson(const QJsonObject &obj) {
        EWPNode node;
        node.id = obj["id"].toInt(-1);
        node.name = obj["name"].toString();
        node.serverPort = obj["serverPort"].toInt(443);
        node.appProtocol = static_cast<AppProtocol>(obj["appProtocol"].toInt(0));
        node.uuid = obj["uuid"].toString();
        node.trojanPassword = obj["trojanPassword"].toString();
        node.transportMode = static_cast<TransportMode>(obj["transportMode"].toInt(0));
        node.wsPath = obj["wsPath"].toString("/");
        node.grpcServiceName = obj["grpcServiceName"].toString("ProxyService");
        node.userAgent = obj["userAgent"].toString();
        node.contentType = obj["contentType"].toString();
        node.xhttpMode = obj["xhttpMode"].toString("auto");
        node.xhttpPath = obj["xhttpPath"].toString("/xhttp");
        node.enableTLS = obj["enableTLS"].toBool(true);
        node.sni = obj["sni"].toString();
        node.minTLSVersion = obj["minTLSVersion"].toString("1.2");
        node.enableECH = obj["enableECH"].toBool(true);
        node.echDomain = obj["echDomain"].toString("cloudflare-ech.com");
        node.dnsServer = obj["dnsServer"].toString("dns.alidns.com/dns-query");
        node.enablePQC = obj["enablePQC"].toBool(false);
        node.enableFlow = obj["enableFlow"].toBool(true);

        // 兼容旧版 nodes.json：旧版 serverAddress 是连接域名，serverIP 是优选IP
        // 新版：serverIP=连接目标，serverAddress=Host
        // 迁移：若旧版有 serverAddress 但无 serverIP，将 serverAddress 迁移到 serverIP
        QString oldServerAddress = obj["serverAddress"].toString();
        QString oldServerIP = obj["serverIP"].toString();
        if (oldServerIP.isEmpty() && !oldServerAddress.isEmpty()) {
            node.serverIP = oldServerAddress;
            node.serverAddress = "";
        } else {
            node.serverIP = oldServerIP;
            node.serverAddress = oldServerAddress;
        }

        return node;
    }

    QString displayType() const {
        QString prefix = (appProtocol == TROJAN) ? "Trojan" : "EWP";
        switch (transportMode) {
            case WS:     return prefix + "-WS";
            case GRPC:   return prefix + "-gRPC";
            case XHTTP:  return prefix + "-XHTTP";
            case H3GRPC: return prefix + "-H3";
            default:     return prefix;
        }
    }

    QString displayAddress() const {
        return QString("%1:%2").arg(serverIP).arg(serverPort);
    }

    QString displayLatency() const {
        if (latency < 0) return "失败";
        if (latency == 0) return "-";
        return QString("%1 ms").arg(latency);
    }

    bool isValid() const {
        if (serverIP.isEmpty()) return false;
        if (appProtocol == TROJAN) return !trojanPassword.isEmpty();
        return !uuid.isEmpty();
    }

    QString displayAuth() const {
        if (appProtocol == TROJAN) {
            if (trojanPassword.length() <= 4) return "****";
            return trojanPassword.left(2) + "****" + trojanPassword.right(2);
        }
        return uuid.left(8) + "...";
    }

    // 返回实际用于连接的 host（server 字段）
    QString effectiveHost() const {
        return serverAddress.isEmpty() ? serverIP : serverAddress;
    }

    // 返回实际用于 TLS SNI 的域名
    QString effectiveSNI() const {
        return sni.isEmpty() ? effectiveHost() : sni;
    }
};
