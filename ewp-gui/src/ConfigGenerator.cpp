#include "ConfigGenerator.h"
#include <QJsonDocument>
#include <QJsonArray>
#include <QFile>
#include <QDebug>

QJsonObject ConfigGenerator::generateClientConfig(const EWPNode &node, const SettingsDialog::AppSettings &settings, bool tunMode)
{
    QJsonObject config;
    
    config["log"] = generateLog();
    
    QJsonArray inbounds;
    inbounds.append(generateInbound(settings, tunMode));
    config["inbounds"] = inbounds;
    
    QJsonArray outbounds;
    outbounds.append(generateOutbound(node));
    config["outbounds"] = outbounds;
    
    config["route"] = generateRoute();
    
    return config;
}

QString ConfigGenerator::generateConfigFile(const EWPNode &node, const SettingsDialog::AppSettings &settings, bool tunMode)
{
    QJsonObject config = generateClientConfig(node, settings, tunMode);
    QJsonDocument doc(config);
    return QString::fromUtf8(doc.toJson(QJsonDocument::Indented));
}

bool ConfigGenerator::saveConfig(const QJsonObject &config, const QString &filePath)
{
    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        qWarning() << "Failed to open config file for writing:" << filePath;
        return false;
    }
    
    QJsonDocument doc(config);
    file.write(doc.toJson(QJsonDocument::Indented));
    file.close();
    
    return true;
}

QJsonObject ConfigGenerator::generateLog()
{
    QJsonObject log;
    log["level"] = "info";
    log["timestamp"] = true;
    return log;
}

QJsonObject ConfigGenerator::generateInbound(const SettingsDialog::AppSettings &settings, bool tunMode)
{
    QJsonObject inbound;
    
    if (tunMode) {
        inbound["type"] = "tun";
        inbound["tag"] = "tun-in";
        inbound["inet4_address"] = settings.tunIP;
        inbound["mtu"] = settings.tunMTU;
        inbound["auto_route"] = settings.tunAutoRoute;
        inbound["strict_route"] = settings.tunStrictRoute;
        inbound["stack"] = settings.tunStack;
        
        // TUN mode DNS - IPv4 and IPv6
        if (!settings.tunnelDNS.isEmpty()) {
            inbound["dns"] = settings.tunnelDNS.trimmed();
        }
        
        if (!settings.tunnelDNSv6.isEmpty()) {
            inbound["ipv6_dns"] = settings.tunnelDNSv6.trimmed();
        }
    } else {
        inbound["type"] = "mixed";
        inbound["tag"] = "mixed-in";
        inbound["listen"] = settings.listenAddr;
        inbound["udp"] = true;
    }
    
    return inbound;
}

QJsonObject ConfigGenerator::generateOutbound(const EWPNode &node)
{
    QJsonObject outbound;
    
    outbound["type"] = (node.appProtocol == EWPNode::TROJAN) ? "trojan" : "ewp";
    outbound["tag"] = "proxy-out";
    outbound["server"] = node.serverAddress;
    outbound["server_port"] = node.serverPort;
    
    if (!node.serverIP.isEmpty()) {
        outbound["server_ip"] = node.serverIP;
    }
    
    if (node.appProtocol == EWPNode::TROJAN) {
        outbound["password"] = node.trojanPassword;
    } else {
        outbound["uuid"] = node.uuid;
    }
    
    outbound["transport"] = generateTransport(node);
    outbound["tls"] = generateTLS(node);
    
    if (node.appProtocol == EWPNode::EWP && node.enableFlow) {
        outbound["flow"] = generateFlow(node);
    }
    
    return outbound;
}

QJsonObject ConfigGenerator::generateTransport(const EWPNode &node)
{
    QJsonObject transport;
    
    switch (node.transportMode) {
        case EWPNode::WS:
            transport["type"] = "ws";
            transport["path"] = node.wsPath;
            break;
            
        case EWPNode::GRPC:
            transport["type"] = "grpc";
            transport["service_name"] = node.grpcServiceName;
            if (!node.userAgent.isEmpty()) {
                transport["user_agent"] = node.userAgent;
            }
            if (!node.contentType.isEmpty()) {
                transport["content_type"] = node.contentType;
            }
            break;
            
        case EWPNode::XHTTP:
            transport["type"] = "xhttp";
            transport["path"] = node.xhttpPath;
            transport["mode"] = node.xhttpMode;
            break;
            
        case EWPNode::H3GRPC:
            transport["type"] = "h3grpc";
            transport["service_name"] = node.grpcServiceName;
            if (!node.userAgent.isEmpty()) {
                transport["user_agent"] = node.userAgent;
            }
            if (!node.contentType.isEmpty()) {
                transport["content_type"] = node.contentType;
            }
            
            QJsonObject grpcWeb;
            grpcWeb["mode"] = "binary";
            grpcWeb["max_message_size"] = 4194304;
            grpcWeb["compression"] = "none";
            transport["grpc_web"] = grpcWeb;
            
            transport["concurrency"] = 4;
            
            QJsonObject quic;
            quic["initial_stream_window_size"] = 6291456;
            quic["max_stream_window_size"] = 16777216;
            quic["initial_connection_window_size"] = 15728640;
            quic["max_connection_window_size"] = 25165824;
            quic["max_idle_timeout"] = "30s";
            quic["keep_alive_period"] = "10s";
            quic["disable_path_mtu_discovery"] = false;
            transport["quic"] = quic;
            break;
    }
    
    return transport;
}

QJsonObject ConfigGenerator::generateTLS(const EWPNode &node)
{
    QJsonObject tls;
    
    tls["enabled"] = true;
    tls["server_name"] = node.serverAddress;
    tls["insecure"] = false;
    
    QJsonArray alpn;
    if (node.transportMode == EWPNode::H3GRPC) {
        alpn.append("h3");
    } else if (node.transportMode == EWPNode::GRPC) {
        alpn.append("h2");
    } else {
        alpn.append("http/1.1");
    }
    tls["alpn"] = alpn;
    
    if (node.enableECH) {
        QJsonObject ech;
        ech["enabled"] = true;
        ech["config_domain"] = node.echDomain;
        ech["doh_server"] = node.dnsServer;
        ech["fallback_on_error"] = true;
        tls["ech"] = ech;
    }
    
    if (node.enablePQC) {
        tls["pqc"] = true;
    }
    
    return tls;
}

QJsonObject ConfigGenerator::generateFlow(const EWPNode &node)
{
    Q_UNUSED(node)
    
    QJsonObject flow;
    flow["enabled"] = true;
    
    QJsonArray padding;
    padding.append(900);
    padding.append(500);
    padding.append(900);
    padding.append(256);
    flow["padding"] = padding;
    
    return flow;
}

QJsonObject ConfigGenerator::generateRoute()
{
    QJsonObject route;
    route["final"] = "proxy-out";
    route["auto_detect_interface"] = true;
    route["rules"] = QJsonArray();
    return route;
}
