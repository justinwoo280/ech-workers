// EWP v2 share-link encoding.
//
// Schema (single line):
//   ewp://<uuid>@<host>:<port>?
//       net=ws|grpc|xhttp|h3grpc&
//       path=<urlencoded>&
//       host=<authority>&
//       sni=<sni>&
//       ech=0|1&
//       doh=<csv-urlencoded>
//   #<name>
//
// Anything from v1 (appProtocol=trojan, password, flow, pqc, tls,
// xhttpMode, userAgent, contentType, dnsServer alias, echDomain
// override) is silently dropped — they have no v2 equivalent and
// keeping them in the URL would mislead users into thinking those
// knobs still mattered.
//
// Inbound parsing tolerates legacy params on a best-effort basis:
// we map `dns=` → `doh=`, `tls=0` → reject the link, otherwise
// quietly ignore unknown query items.

#include "ShareLink.h"

#include <QUrl>
#include <QUrlQuery>
#include <QStringList>
#include <QRegularExpression>

QList<EWPNode> ShareLink::parseLinks(const QString &text)
{
    QList<EWPNode> out;
    const QStringList lines = text.split(QRegularExpression("[\r\n]+"), Qt::SkipEmptyParts);
    for (const QString &line : lines) {
        const QString trimmed = line.trimmed();
        if (trimmed.isEmpty() || trimmed.startsWith('#')) continue;
        EWPNode n = parseLink(trimmed);
        if (!n.uuid.isEmpty() && !n.server.isEmpty()) out.append(n);
    }
    return out;
}

EWPNode ShareLink::parseLink(const QString &link)
{
    EWPNode node;

    QUrl url(link);
    if (!url.isValid() || url.scheme().toLower() != "ewp") return node;

    const QString uuid = url.userName();
    const QString host = url.host();
    if (uuid.isEmpty() || host.isEmpty()) return node;

    // Light validation: 32 hex chars exactly. Anything else is junk.
    static const QRegularExpression hexRe("^[0-9a-fA-F]{32}$");
    if (!hexRe.match(uuid).hasMatch()) return node;

    node.uuid       = uuid.toLower();
    node.server     = host;
    node.serverPort = url.port(443);

    if (!url.fragment().isEmpty()) {
        node.name = QUrl::fromPercentEncoding(url.fragment().toUtf8());
    }

    QUrlQuery q(url);

    const QString net = q.queryItemValue("net").toLower();
    if      (net == "grpc")             node.transportMode = EWPNode::GRPC;
    else if (net == "xhttp")            node.transportMode = EWPNode::XHTTP;
    else if (net == "h3" || net == "h3grpc") node.transportMode = EWPNode::H3GRPC;
    else                                node.transportMode = EWPNode::WS;

    const QString path = QUrl::fromPercentEncoding(q.queryItemValue("path").toUtf8());
    if (!path.isEmpty()) {
        switch (node.transportMode) {
            case EWPNode::WS:     node.wsPath = path; break;
            case EWPNode::GRPC:   node.grpcServiceName = path; break;
            case EWPNode::XHTTP:  node.xhttpPath = path; break;
            case EWPNode::H3GRPC: node.grpcServiceName = path; break;
        }
    }

    if (q.hasQueryItem("host")) node.host = q.queryItemValue("host");
    if (q.hasQueryItem("sni"))  node.sni  = q.queryItemValue("sni");

    // ECH defaults to true; only an explicit "0" turns it off.
    if (q.hasQueryItem("ech")) node.enableECH = q.queryItemValue("ech") != "0";
    if (q.hasQueryItem("ech_domain")) node.echDomain = q.queryItemValue("ech_domain");

    // DoH list — accept both v2 `doh=` and legacy `dns=` aliases.
    QString doh = q.queryItemValue("doh");
    if (doh.isEmpty()) doh = q.queryItemValue("dns");
    if (!doh.isEmpty()) node.dohServers = QUrl::fromPercentEncoding(doh.toUtf8());

    // Legacy guard: a v1 share link with tls=0 (no TLS) is incompatible
    // with v2's mandatory TLS-1.3 floor; refuse to import it so the
    // user is not silently upgraded to "your old plaintext config now
    // has TLS forced on".
    if (q.queryItemValue("tls") == "0") {
        return EWPNode{};
    }

    return node;
}

QString ShareLink::generateLink(const EWPNode &node)
{
    QUrl url;
    url.setScheme("ewp");
    url.setUserName(node.uuid);
    url.setHost(node.server);
    if (node.serverPort != 443) url.setPort(node.serverPort);
    url.setPath("/");

    QUrlQuery q;

    const char *net = "ws";
    QString path;
    switch (node.transportMode) {
        case EWPNode::WS:     net = "ws";     path = node.wsPath;          break;
        case EWPNode::GRPC:   net = "grpc";   path = node.grpcServiceName; break;
        case EWPNode::XHTTP:  net = "xhttp";  path = node.xhttpPath;       break;
        case EWPNode::H3GRPC: net = "h3grpc"; path = node.grpcServiceName; break;
    }
    q.addQueryItem("net", net);
    if (!path.isEmpty() && path != "/") {
        q.addQueryItem("path", QString::fromUtf8(QUrl::toPercentEncoding(path)));
    }
    if (!node.host.isEmpty()) q.addQueryItem("host", node.host);
    if (!node.sni.isEmpty())  q.addQueryItem("sni",  node.sni);
    if (!node.enableECH)        q.addQueryItem("ech", "0");
    if (!node.echDomain.isEmpty()) q.addQueryItem("ech_domain", node.echDomain);

    if (!node.dohServers.isEmpty()) {
        q.addQueryItem("doh", QString::fromUtf8(QUrl::toPercentEncoding(node.dohServers)));
    }

    url.setQuery(q);
    if (!node.name.isEmpty()) {
        url.setFragment(QString::fromUtf8(QUrl::toPercentEncoding(node.name)));
    }
    return url.toString(QUrl::FullyEncoded);
}
