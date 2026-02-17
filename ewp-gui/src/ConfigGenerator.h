#pragma once

#include <QString>
#include <QJsonObject>
#include "EWPNode.h"
#include "SettingsDialog.h"

class ConfigGenerator
{
public:
    static QJsonObject generateClientConfig(const EWPNode &node, const SettingsDialog::AppSettings &settings, bool tunMode = false);
    
    static QString generateConfigFile(const EWPNode &node, const SettingsDialog::AppSettings &settings, bool tunMode = false);
    
    static bool saveConfig(const QJsonObject &config, const QString &filePath);

private:
    static QJsonObject generateInbound(const SettingsDialog::AppSettings &settings, bool tunMode);
    static QJsonObject generateOutbound(const EWPNode &node);
    static QJsonObject generateTransport(const EWPNode &node);
    static QJsonObject generateTLS(const EWPNode &node);
    static QJsonObject generateFlow(const EWPNode &node);
    static QJsonObject generateRoute();
    static QJsonObject generateLog();
};
