#pragma once

#include <QMainWindow>
#include <QSystemTrayIcon>
#include <QTableWidget>
#include <QTextBrowser>
#include <QCheckBox>
#include <QLabel>
#include <QMenu>
#include <QTimer>

#include "EWPNode.h"
#include "CoreProcess.h"
#include "NodeManager.h"
#include "SystemProxy.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onAddNode();
    void onEditNode();
    void onDeleteNode();
    void onDuplicateNode();
    
    void onTestSelected();
    void onTestAll();
    
    void onImportFromClipboard();
    void onExportToClipboard();
    
    void onStartStop();
    void onNodeDoubleClicked(int row, int column);
    
    void onSystemProxyToggled(bool checked);
    void onTunModeToggled(bool checked);
    
    void updateNodeList();
    void updateStatusBar();
    void appendLog(const QString &message);
    
    void onTrayIconActivated(QSystemTrayIcon::ActivationReason reason);
    void showNodeContextMenu(const QPoint &pos);

protected:
    void closeEvent(QCloseEvent *event) override;

private:
    void setupConnections();
    void setupSystemTray();
    void setupNodeTable();
    void loadSettings();
    void saveSettings();
    
    Ui::MainWindow *ui;
    
    CoreProcess *coreProcess;
    NodeManager *nodeManager;
    SystemProxy *systemProxy;
    
    QSystemTrayIcon *trayIcon;
    QMenu *trayMenu;
    
    int currentNodeId = -1;
    bool isRunning = false;
};
