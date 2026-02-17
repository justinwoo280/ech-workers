#include "SettingsDialog.h"
#include "ui_Settings.h"

SettingsDialog::SettingsDialog(QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::Settings)
{
    ui->setupUi(this);
    loadSettings();
}

SettingsDialog::~SettingsDialog()
{
    delete ui;
}

void SettingsDialog::loadSettings()
{
    AppSettings settings = loadFromRegistry();
    setSettings(settings);
}

SettingsDialog::AppSettings SettingsDialog::getSettings() const
{
    AppSettings settings;
    
    settings.listenAddr = ui->editListenAddr->text();
    settings.autoStart = ui->checkAutoStart->isChecked();
    settings.minimizeToTray = ui->checkMinimizeToTray->isChecked();
    
    settings.tunnelDNS = ui->editTunnelDNS->text();
    settings.tunnelDNSv6 = ui->editTunnelDNSv6->text();
    
    settings.tunIP = ui->editTunIP->text();
    settings.tunMTU = ui->spinTunMTU->value();
    settings.tunStack = ui->comboTunStack->currentText();
    settings.tunAutoRoute = ui->checkTunAutoRoute->isChecked();
    settings.tunStrictRoute = ui->checkTunStrictRoute->isChecked();
    
    return settings;
}

void SettingsDialog::setSettings(const AppSettings &settings)
{
    ui->editListenAddr->setText(settings.listenAddr);
    ui->checkAutoStart->setChecked(settings.autoStart);
    ui->checkMinimizeToTray->setChecked(settings.minimizeToTray);
    
    ui->editTunnelDNS->setText(settings.tunnelDNS);
    ui->editTunnelDNSv6->setText(settings.tunnelDNSv6);
    
    ui->editTunIP->setText(settings.tunIP);
    ui->spinTunMTU->setValue(settings.tunMTU);
    
    int stackIndex = ui->comboTunStack->findText(settings.tunStack);
    if (stackIndex >= 0) {
        ui->comboTunStack->setCurrentIndex(stackIndex);
    }
    
    ui->checkTunAutoRoute->setChecked(settings.tunAutoRoute);
    ui->checkTunStrictRoute->setChecked(settings.tunStrictRoute);
}

void SettingsDialog::accept()
{
    AppSettings settings = getSettings();
    saveToRegistry(settings);
    QDialog::accept();
}

SettingsDialog::AppSettings SettingsDialog::loadFromRegistry()
{
    QSettings settings("EWP", "EWP-GUI");
    
    AppSettings appSettings;
    appSettings.listenAddr = settings.value("app/listenAddr", "127.0.0.1:30000").toString();
    appSettings.autoStart = settings.value("app/autoStart", false).toBool();
    appSettings.minimizeToTray = settings.value("app/minimizeToTray", true).toBool();
    
    appSettings.tunnelDNS = settings.value("tun/dns", "8.8.8.8").toString();
    appSettings.tunnelDNSv6 = settings.value("tun/ipv6_dns", "2001:4860:4860::8888").toString();
    
    appSettings.tunIP = settings.value("tun/ip", "10.0.85.2/24").toString();
    appSettings.tunMTU = settings.value("tun/mtu", 1380).toInt();
    appSettings.tunStack = settings.value("tun/stack", "system").toString();
    appSettings.tunAutoRoute = settings.value("tun/autoRoute", true).toBool();
    appSettings.tunStrictRoute = settings.value("tun/strictRoute", false).toBool();
    
    return appSettings;
}

void SettingsDialog::saveToRegistry(const AppSettings &settings)
{
    QSettings qSettings("EWP", "EWP-GUI");
    
    qSettings.setValue("app/listenAddr", settings.listenAddr);
    qSettings.setValue("app/autoStart", settings.autoStart);
    qSettings.setValue("app/minimizeToTray", settings.minimizeToTray);
    
    qSettings.setValue("tun/dns", settings.tunnelDNS);
    qSettings.setValue("tun/ipv6_dns", settings.tunnelDNSv6);
    
    qSettings.setValue("tun/ip", settings.tunIP);
    qSettings.setValue("tun/mtu", settings.tunMTU);
    qSettings.setValue("tun/stack", settings.tunStack);
    qSettings.setValue("tun/autoRoute", settings.tunAutoRoute);
    qSettings.setValue("tun/strictRoute", settings.tunStrictRoute);
}

SettingsDialog::AppSettings SettingsDialog::defaultSettings()
{
    AppSettings settings;
    settings.listenAddr = "127.0.0.1:30000";
    settings.autoStart = false;
    settings.minimizeToTray = true;
    
    settings.tunnelDNS = "8.8.8.8";
    settings.tunnelDNSv6 = "2001:4860:4860::8888";
    
    settings.tunIP = "10.0.85.2/24";
    settings.tunMTU = 1380;
    settings.tunStack = "system";
    settings.tunAutoRoute = true;
    settings.tunStrictRoute = false;
    
    return settings;
}
