#pragma once

#include <QString>
#include <QJsonObject>

// EWP 节点配置结构
struct EWPNode {
    int id = -1;
    QString name;
    QString serverAddress;
    int serverPort = 443;
    QString uuid;
    QString serverIP;          // 优选 IP
    
    // 应用层协议: 0=EWP, 1=Trojan
    enum AppProtocol { EWP = 0, TROJAN = 1 };
    AppProtocol appProtocol = EWP;
    
    // Trojan 配置
    QString trojanPassword;    // Trojan 密码
    
    // 传输协议: 0=WebSocket, 1=gRPC, 2=XHTTP, 3=H3gRPC
    enum TransportMode { WS = 0, GRPC = 1, XHTTP = 2, H3GRPC = 3 };
    TransportMode transportMode = WS;
    
    // WebSocket 配置
    QString wsPath = "/";              // WebSocket 路径
    
    // gRPC / H3gRPC 配置
    QString grpcServiceName = "ProxyService";   // gRPC 服务名
    QString userAgent;                 // 自定义 User-Agent (anti-DPI)
    QString contentType;               // 自定义 Content-Type (anti-DPI)
    
    // ECH 配置
    bool enableECH = true;
    QString echDomain = "cloudflare-ech.com";
    QString dnsServer = "dns.alidns.com/dns-query";
    
    // 高级配置
    bool enableFlow = true;
    bool enablePQC = false;
    
    // XHTTP 配置
    QString xhttpMode = "auto";
    QString xhttpPath = "/xhttp";
    
    // 测试结果
    int latency = 0;  // ms, -1 表示失败, 0 表示未测试
    
    // 序列化
    QJsonObject toJson() const {
        QJsonObject obj;
        obj["id"] = id;
        obj["name"] = name;
        obj["serverAddress"] = serverAddress;
        obj["serverPort"] = serverPort;
        obj["uuid"] = uuid;
        obj["serverIP"] = serverIP;
        obj["appProtocol"] = static_cast<int>(appProtocol);
        obj["trojanPassword"] = trojanPassword;
        obj["transportMode"] = static_cast<int>(transportMode);
        obj["wsPath"] = wsPath;
        obj["grpcServiceName"] = grpcServiceName;
        obj["userAgent"] = userAgent;
        obj["contentType"] = contentType;
        obj["enableECH"] = enableECH;
        obj["echDomain"] = echDomain;
        obj["dnsServer"] = dnsServer;
        obj["enableFlow"] = enableFlow;
        obj["enablePQC"] = enablePQC;
        obj["xhttpMode"] = xhttpMode;
        obj["xhttpPath"] = xhttpPath;
        return obj;
    }
    
    static EWPNode fromJson(const QJsonObject &obj) {
        EWPNode node;
        node.id = obj["id"].toInt(-1);
        node.name = obj["name"].toString();
        node.serverAddress = obj["serverAddress"].toString();
        node.serverPort = obj["serverPort"].toInt(443);
        node.uuid = obj["uuid"].toString();
        node.serverIP = obj["serverIP"].toString();
        node.appProtocol = static_cast<AppProtocol>(obj["appProtocol"].toInt(0));
        node.trojanPassword = obj["trojanPassword"].toString();
        node.transportMode = static_cast<TransportMode>(obj["transportMode"].toInt(0));
        node.wsPath = obj["wsPath"].toString("/");
        node.grpcServiceName = obj["grpcServiceName"].toString("ProxyService");
        node.userAgent = obj["userAgent"].toString();
        node.contentType = obj["contentType"].toString();
        node.enableECH = obj["enableECH"].toBool(true);
        node.echDomain = obj["echDomain"].toString("cloudflare-ech.com");
        node.dnsServer = obj["dnsServer"].toString("dns.alidns.com/dns-query");
        node.enableFlow = obj["enableFlow"].toBool(true);
        node.enablePQC = obj["enablePQC"].toBool(false);
        node.xhttpMode = obj["xhttpMode"].toString("auto");
        node.xhttpPath = obj["xhttpPath"].toString("/xhttp");
        return node;
    }
    
    QString displayType() const {
        QString prefix = (appProtocol == TROJAN) ? "Trojan" : "EWP";
        switch (transportMode) {
            case WS: return prefix + "-WS";
            case GRPC: return prefix + "-gRPC";
            case XHTTP: return prefix + "-XHTTP";
            case H3GRPC: return prefix + "-H3";
            default: return prefix;
        }
    }
    
    QString displayAddress() const {
        return QString("%1:%2").arg(serverAddress).arg(serverPort);
    }
    
    QString displayLatency() const {
        if (latency < 0) return "失败";
        if (latency == 0) return "-";
        return QString("%1 ms").arg(latency);
    }
    
    bool isValid() const {
        if (serverAddress.isEmpty()) return false;
        if (appProtocol == TROJAN) {
            return !trojanPassword.isEmpty();
        }
        return !uuid.isEmpty();
    }
    
    // 获取认证信息（用于显示）
    QString displayAuth() const {
        if (appProtocol == TROJAN) {
            if (trojanPassword.length() <= 4) return "****";
            return trojanPassword.left(2) + "****" + trojanPassword.right(2);
        }
        return uuid.left(8) + "...";
    }
};
