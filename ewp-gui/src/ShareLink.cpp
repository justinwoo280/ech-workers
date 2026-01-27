#include "ShareLink.h"
#include <QUrl>
#include <QUrlQuery>
#include <QRegularExpression>

QList<EWPNode> ShareLink::parseLinks(const QString &text)
{
    QList<EWPNode> nodes;
    
    QStringList lines = text.split(QRegularExpression("[\\r\\n]+"), Qt::SkipEmptyParts);
    
    for (const auto &line : lines) {
        QString trimmed = line.trimmed();
        if (trimmed.startsWith("ewp://")) {
            EWPNode node = parseLink(trimmed);
            if (node.isValid()) {
                nodes.append(node);
            }
        }
    }
    
    return nodes;
}

EWPNode ShareLink::parseLink(const QString &link)
{
    EWPNode node;
    
    if (!link.startsWith("ewp://")) {
        return node;
    }
    
    QUrl url(link);
    if (!url.isValid()) {
        return node;
    }
    
    // 解析 UUID
    node.uuid = url.userName();
    if (node.uuid.isEmpty()) {
        return node;
    }
    
    // 解析服务器地址和端口
    node.serverAddress = url.host();
    node.serverPort = url.port(443);
    
    // 解析节点名称
    node.name = url.fragment();
    if (node.name.isEmpty()) {
        node.name = node.serverAddress;
    }
    
    // 解析查询参数
    QUrlQuery query(url);
    
    // 传输模式
    QString mode = query.queryItemValue("mode");
    if (mode == "grpc") {
        node.transportMode = EWPNode::GRPC;
    } else if (mode == "xhttp") {
        node.transportMode = EWPNode::XHTTP;
    } else {
        node.transportMode = EWPNode::WS;
    }
    
    // WebSocket 路径
    QString wsPath = query.queryItemValue("wsPath");
    if (!wsPath.isEmpty()) {
        node.wsPath = wsPath;
    }
    
    // gRPC 服务名
    QString grpcService = query.queryItemValue("grpcService");
    if (!grpcService.isEmpty()) {
        node.grpcServiceName = grpcService;
    }
    
    // 优选 IP
    node.serverIP = query.queryItemValue("ip");
    
    // ECH 配置
    node.enableECH = query.queryItemValue("ech") != "0";
    QString echDomain = query.queryItemValue("echDomain");
    if (!echDomain.isEmpty()) {
        node.echDomain = echDomain;
    }
    QString dnsServer = query.queryItemValue("dns");
    if (!dnsServer.isEmpty()) {
        node.dnsServer = dnsServer;
    }
    
    // 高级配置
    node.enableFlow = query.queryItemValue("flow") != "0";
    node.enablePQC = query.queryItemValue("pqc") == "1";
    
    // XHTTP 配置
    QString xhttpMode = query.queryItemValue("xhttpMode");
    if (!xhttpMode.isEmpty()) {
        node.xhttpMode = xhttpMode;
    }
    QString xhttpPath = query.queryItemValue("xhttpPath");
    if (!xhttpPath.isEmpty()) {
        node.xhttpPath = xhttpPath;
    }
    
    return node;
}

QString ShareLink::generateLink(const EWPNode &node)
{
    QUrl url;
    url.setScheme("ewp");
    url.setUserName(node.uuid);
    url.setHost(node.serverAddress);
    url.setPort(node.serverPort);
    url.setFragment(node.name);
    
    QUrlQuery query;
    
    // 传输模式
    switch (node.transportMode) {
        case EWPNode::GRPC:
            query.addQueryItem("mode", "grpc");
            // gRPC 服务名
            if (node.grpcServiceName != "ProxyService") {
                query.addQueryItem("grpcService", node.grpcServiceName);
            }
            break;
        case EWPNode::XHTTP:
            query.addQueryItem("mode", "xhttp");
            break;
        default:
            query.addQueryItem("mode", "ws");
            // WebSocket 路径
            if (node.wsPath != "/") {
                query.addQueryItem("wsPath", node.wsPath);
            }
            break;
    }
    
    // 优选 IP
    if (!node.serverIP.isEmpty()) {
        query.addQueryItem("ip", node.serverIP);
    }
    
    // ECH 配置
    query.addQueryItem("ech", node.enableECH ? "1" : "0");
    if (node.enableECH && node.echDomain != "cloudflare-ech.com") {
        query.addQueryItem("echDomain", node.echDomain);
    }
    if (node.enableECH && node.dnsServer != "dns.alidns.com/dns-query") {
        query.addQueryItem("dns", node.dnsServer);
    }
    
    // 高级配置
    query.addQueryItem("flow", node.enableFlow ? "1" : "0");
    query.addQueryItem("pqc", node.enablePQC ? "1" : "0");
    
    // XHTTP 配置
    if (node.transportMode == EWPNode::XHTTP) {
        if (node.xhttpMode != "auto") {
            query.addQueryItem("xhttpMode", node.xhttpMode);
        }
        if (node.xhttpPath != "/xhttp") {
            query.addQueryItem("xhttpPath", node.xhttpPath);
        }
    }
    
    url.setQuery(query);
    return url.toString();
}
