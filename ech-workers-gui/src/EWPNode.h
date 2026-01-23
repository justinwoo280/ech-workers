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
    
    // 传输协议: 0=WebSocket, 1=gRPC, 2=XHTTP
    enum TransportMode { WS = 0, GRPC = 1, XHTTP = 2 };
    TransportMode transportMode = WS;
    
    // WebSocket 配置
    QString wsPath = "/";              // WebSocket 路径
    
    // gRPC 配置
    QString grpcServiceName = "ProxyService";  // gRPC 服务名（与服务端 GRPC_SERVICE 环境变量对应）
    
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
        obj["transportMode"] = static_cast<int>(transportMode);
        obj["wsPath"] = wsPath;
        obj["grpcServiceName"] = grpcServiceName;
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
        node.transportMode = static_cast<TransportMode>(obj["transportMode"].toInt(0));
        node.wsPath = obj["wsPath"].toString("/");
        node.grpcServiceName = obj["grpcServiceName"].toString("ProxyService");
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
        switch (transportMode) {
            case WS: return "EWP-WS";
            case GRPC: return "EWP-gRPC";
            case XHTTP: return "EWP-XHTTP";
            default: return "EWP";
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
        return !serverAddress.isEmpty() && !uuid.isEmpty();
    }
};
