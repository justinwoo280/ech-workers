#pragma once

#include <QDialog>
#include <QSettings>

namespace Ui {
class Settings;
}

class SettingsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SettingsDialog(QWidget *parent = nullptr);
    ~SettingsDialog();
    
    struct AppSettings {
        QString listenAddr;
        bool autoStart;
        bool minimizeToTray;
        
        // TUN DNS settings
        QString tunnelDNS;
        QString tunnelDNSv6;
        
        // TUN settings
        QString tunIP;
        int tunMTU;
        QString tunStack;
        bool tunAutoRoute;
        bool tunStrictRoute;
    };
    
    AppSettings getSettings() const;
    void setSettings(const AppSettings &settings);
    
    static AppSettings loadFromRegistry();
    static void saveToRegistry(const AppSettings &settings);
    static AppSettings defaultSettings();

private slots:
    void accept() override;
    
private:
    Ui::Settings *ui;
    void loadSettings();
};
