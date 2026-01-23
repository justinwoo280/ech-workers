#pragma once

#include <QString>
#include <QList>
#include "EWPNode.h"

class ShareLink
{
public:
    // 解析分享链接（支持多行）
    static QList<EWPNode> parseLinks(const QString &text);
    
    // 解析单个链接
    static EWPNode parseLink(const QString &link);
    
    // 生成分享链接
    static QString generateLink(const EWPNode &node);
};
