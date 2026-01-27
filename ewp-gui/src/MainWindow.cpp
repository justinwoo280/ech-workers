#include "MainWindow.h"
#include "ui_MainWindow.h"

#include <QMessageBox>
#include <QInputDialog>
#include <QClipboard>
#include <QCloseEvent>
#include <QSettings>
#include <QUuid>

#include "ShareLink.h"
#include "NodeTester.h"
#include "EditNodeDialog.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    
    setWindowTitle("EWP GUI");
    
    // 初始化管理器
    coreProcess = new CoreProcess(this);
    nodeManager = new NodeManager(this);
    systemProxy = new SystemProxy(this);
    
    setupConnections();
    setupSystemTray();
    setupNodeTable();
    loadSettings();
    
    updateNodeList();
    updateStatusBar();
}

MainWindow::~MainWindow()
{
    saveSettings();
    if (isRunning) {
        coreProcess->stop();
        systemProxy->disable();
    }
    delete ui;
}

void MainWindow::setupConnections()
{
    // 核心进程信号
    connect(coreProcess, &CoreProcess::started, this, [this]() {
        isRunning = true;
        appendLog("✅ 代理已启动");
        updateStatusBar();
    });
    
    connect(coreProcess, &CoreProcess::stopped, this, [this]() {
        isRunning = false;
        appendLog("⏹️ 代理已停止");
        updateStatusBar();
    });
    
    connect(coreProcess, &CoreProcess::errorOccurred, this, [this](const QString &error) {
        appendLog("❌ 错误: " + error);
        QMessageBox::critical(this, "错误", error);
    });
    
    connect(coreProcess, &CoreProcess::logReceived, this, &MainWindow::appendLog);
    
    // 节点表格双击
    connect(ui->nodeTable, &QTableWidget::cellDoubleClicked, 
            this, &MainWindow::onNodeDoubleClicked);
    
    // 节点表格右键菜单
    ui->nodeTable->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(ui->nodeTable, &QTableWidget::customContextMenuRequested,
            this, &MainWindow::showNodeContextMenu);
    
    // 系统代理复选框
    connect(ui->checkSystemProxy, &QCheckBox::toggled, 
            this, &MainWindow::onSystemProxyToggled);
    connect(ui->checkTunMode, &QCheckBox::toggled, 
            this, &MainWindow::onTunModeToggled);
    
    // 工具栏按钮
    connect(ui->btnAdd, &QPushButton::clicked, this, &MainWindow::onAddNode);
    connect(ui->btnEdit, &QPushButton::clicked, this, &MainWindow::onEditNode);
    connect(ui->btnDelete, &QPushButton::clicked, this, &MainWindow::onDeleteNode);
    connect(ui->btnTest, &QPushButton::clicked, this, &MainWindow::onTestSelected);
    connect(ui->btnTestAll, &QPushButton::clicked, this, &MainWindow::onTestAll);
    connect(ui->btnImport, &QPushButton::clicked, this, &MainWindow::onImportFromClipboard);
    connect(ui->btnExport, &QPushButton::clicked, this, &MainWindow::onExportToClipboard);
    connect(ui->btnStartStop, &QPushButton::clicked, this, &MainWindow::onStartStop);
}

void MainWindow::setupSystemTray()
{
    trayIcon = new QSystemTrayIcon(this);
    
    // 使用自定义图标
    trayIcon->setIcon(QIcon(":/icons/logo.ico"));
    trayIcon->setToolTip("EWP GUI");
    
    // 检查系统托盘支持
    if (!QSystemTrayIcon::isSystemTrayAvailable()) {
        qWarning() << "System tray is not available";
        return;
    }
    
    trayMenu = new QMenu(this);
    
    auto showAction = trayMenu->addAction("显示主窗口");
    connect(showAction, &QAction::triggered, this, [this]() {
        show();
        raise();
        activateWindow();
    });
    
    trayMenu->addSeparator();
    
    auto startStopAction = trayMenu->addAction("启动/停止");
    connect(startStopAction, &QAction::triggered, this, &MainWindow::onStartStop);
    
    trayMenu->addSeparator();
    
    auto quitAction = trayMenu->addAction("退出");
    connect(quitAction, &QAction::triggered, qApp, &QApplication::quit);
    
    trayIcon->setContextMenu(trayMenu);
    connect(trayIcon, &QSystemTrayIcon::activated, 
            this, &MainWindow::onTrayIconActivated);
    
    // 只有在系统托盘可用时才显示托盘图标
    if (QSystemTrayIcon::isSystemTrayAvailable()) {
        trayIcon->show();
    }
}

void MainWindow::setupNodeTable()
{
    ui->nodeTable->setColumnCount(5);
    ui->nodeTable->setHorizontalHeaderLabels({"类型", "地址", "名称", "延迟", "状态"});
    ui->nodeTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->nodeTable->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->nodeTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->nodeTable->setAlternatingRowColors(true);
    ui->nodeTable->horizontalHeader()->setStretchLastSection(true);
    ui->nodeTable->verticalHeader()->setVisible(false);
}

void MainWindow::updateNodeList()
{
    auto nodes = nodeManager->getAllNodes();
    
    ui->nodeTable->setRowCount(nodes.size());
    
    for (int i = 0; i < nodes.size(); ++i) {
        const auto &node = nodes[i];
        
        ui->nodeTable->setItem(i, 0, new QTableWidgetItem(node.displayType()));
        ui->nodeTable->setItem(i, 1, new QTableWidgetItem(node.displayAddress()));
        ui->nodeTable->setItem(i, 2, new QTableWidgetItem(node.name));
        ui->nodeTable->setItem(i, 3, new QTableWidgetItem(node.displayLatency()));
        
        QString status = (node.id == currentNodeId && isRunning) ? "运行中" : "";
        ui->nodeTable->setItem(i, 4, new QTableWidgetItem(status));
        
        // 存储节点 ID
        ui->nodeTable->item(i, 0)->setData(Qt::UserRole, node.id);
        
        // 高亮当前运行的节点
        if (node.id == currentNodeId && isRunning) {
            for (int j = 0; j < 5; ++j) {
                ui->nodeTable->item(i, j)->setBackground(QColor(200, 255, 200));
            }
        }
    }
    
    ui->nodeTable->resizeColumnsToContents();
}

void MainWindow::updateStatusBar()
{
    if (isRunning) {
        auto node = nodeManager->getNode(currentNodeId);
        ui->labelStatus->setText(QString("运行中: %1 | 监听: %2")
            .arg(node.name)
            .arg(coreProcess->getListenAddr()));
        ui->btnStartStop->setText("停止");
    } else {
        ui->labelStatus->setText("未运行");
        ui->btnStartStop->setText("启动");
    }
}

void MainWindow::appendLog(const QString &message)
{
    ui->logBrowser->append(message);
}

void MainWindow::onAddNode()
{
    EWPNode node;
    node.name = "新节点";
    node.serverAddress = "example.com";
    node.serverPort = 443;
    node.uuid = QUuid::createUuid().toString(QUuid::WithoutBraces);
    
    EditNodeDialog dialog(this);
    dialog.setWindowTitle("添加节点");
    dialog.setNode(node);
    
    if (dialog.exec() == QDialog::Accepted) {
        EWPNode newNode = dialog.getNode();
        nodeManager->addNode(newNode);
        updateNodeList();
        appendLog(QString("✅ 已添加节点: %1").arg(newNode.name));
    }
}

void MainWindow::onEditNode()
{
    int row = ui->nodeTable->currentRow();
    if (row < 0) return;
    
    int nodeId = ui->nodeTable->item(row, 0)->data(Qt::UserRole).toInt();
    EWPNode node = nodeManager->getNode(nodeId);
    
    EditNodeDialog dialog(this);
    dialog.setWindowTitle("编辑节点");
    dialog.setNode(node);
    
    if (dialog.exec() == QDialog::Accepted) {
        EWPNode updatedNode = dialog.getNode();
        updatedNode.id = nodeId;
        nodeManager->updateNode(updatedNode);
        updateNodeList();
        appendLog(QString("✅ 已更新节点: %1").arg(updatedNode.name));
    }
}

void MainWindow::onDeleteNode()
{
    int row = ui->nodeTable->currentRow();
    if (row < 0) return;
    
    int nodeId = ui->nodeTable->item(row, 0)->data(Qt::UserRole).toInt();
    
    if (QMessageBox::question(this, "确认删除", "确定要删除这个节点吗？") 
        == QMessageBox::Yes) {
        nodeManager->removeNode(nodeId);
        updateNodeList();
    }
}

void MainWindow::onDuplicateNode()
{
    int row = ui->nodeTable->currentRow();
    if (row < 0) return;
    
    int nodeId = ui->nodeTable->item(row, 0)->data(Qt::UserRole).toInt();
    auto node = nodeManager->getNode(nodeId);
    node.id = -1;
    node.name += " (副本)";
    
    nodeManager->addNode(node);
    updateNodeList();
}

void MainWindow::onTestSelected()
{
    int row = ui->nodeTable->currentRow();
    if (row < 0) return;
    
    int nodeId = ui->nodeTable->item(row, 0)->data(Qt::UserRole).toInt();
    auto node = nodeManager->getNode(nodeId);
    
    appendLog(QString("正在测试节点: %1").arg(node.name));
    
    // 异步测试
    NodeTester::testNode(node, [this, nodeId](int latency) {
        nodeManager->updateLatency(nodeId, latency);
        updateNodeList();
        appendLog(QString("测试完成: %1 ms").arg(latency > 0 ? QString::number(latency) : "失败"));
    });
}

void MainWindow::onTestAll()
{
    auto nodes = nodeManager->getAllNodes();
    appendLog(QString("开始测试所有节点 (%1 个)").arg(nodes.size()));
    
    for (const auto &node : nodes) {
        NodeTester::testNode(node, [this, id = node.id](int latency) {
            nodeManager->updateLatency(id, latency);
            updateNodeList();
        });
    }
}

void MainWindow::onImportFromClipboard()
{
    QString text = QApplication::clipboard()->text();
    if (text.isEmpty()) {
        QMessageBox::warning(this, "导入失败", "剪贴板为空");
        return;
    }
    
    auto nodes = ShareLink::parseLinks(text);
    if (nodes.isEmpty()) {
        QMessageBox::warning(this, "导入失败", "未找到有效的分享链接");
        return;
    }
    
    for (auto &node : nodes) {
        nodeManager->addNode(node);
    }
    
    updateNodeList();
    QMessageBox::information(this, "导入成功", 
        QString("成功导入 %1 个节点").arg(nodes.size()));
}

void MainWindow::onExportToClipboard()
{
    int row = ui->nodeTable->currentRow();
    if (row < 0) {
        QMessageBox::warning(this, "导出失败", "请先选择一个节点");
        return;
    }
    
    int nodeId = ui->nodeTable->item(row, 0)->data(Qt::UserRole).toInt();
    auto node = nodeManager->getNode(nodeId);
    
    QString link = ShareLink::generateLink(node);
    QApplication::clipboard()->setText(link);
    
    QMessageBox::information(this, "导出成功", "分享链接已复制到剪贴板");
}

void MainWindow::onStartStop()
{
    if (isRunning) {
        coreProcess->stop();
        if (ui->checkSystemProxy->isChecked()) {
            systemProxy->disable();
        }
    } else {
        int row = ui->nodeTable->currentRow();
        if (row < 0) {
            QMessageBox::warning(this, "启动失败", "请先选择一个节点");
            return;
        }
        
        int nodeId = ui->nodeTable->item(row, 0)->data(Qt::UserRole).toInt();
        auto node = nodeManager->getNode(nodeId);
        
        if (!node.isValid()) {
            QMessageBox::warning(this, "启动失败", "节点配置无效");
            return;
        }
        
        currentNodeId = nodeId;
        bool tunMode = ui->checkTunMode->isChecked();
        
        if (coreProcess->start(node, tunMode)) {
            if (ui->checkSystemProxy->isChecked() && !tunMode) {
                systemProxy->enable(coreProcess->getListenAddr());
            }
        }
    }
    
    updateNodeList();
}

void MainWindow::onNodeDoubleClicked(int row, int column)
{
    Q_UNUSED(column)
    
    int nodeId = ui->nodeTable->item(row, 0)->data(Qt::UserRole).toInt();
    
    // 如果双击的是当前运行的节点，则停止
    if (isRunning && nodeId == currentNodeId) {
        onStartStop();
        return;
    }
    
    // 如果正在运行其他节点，先停止再切换
    if (isRunning) {
        appendLog("🔄 切换节点...");
        coreProcess->stop();
        if (ui->checkSystemProxy->isChecked()) {
            systemProxy->disable();
        }
        isRunning = false;
    }
    
    // 启动新节点
    currentNodeId = nodeId;
    auto node = nodeManager->getNode(nodeId);
    
    if (!node.isValid()) {
        QMessageBox::warning(this, "启动失败", "节点配置无效");
        return;
    }
    
    bool tunMode = ui->checkTunMode->isChecked();
    
    if (coreProcess->start(node, tunMode)) {
        if (ui->checkSystemProxy->isChecked() && !tunMode) {
            systemProxy->enable(coreProcess->getListenAddr());
        }
    }
    
    updateNodeList();
}

void MainWindow::onSystemProxyToggled(bool checked)
{
    if (isRunning && !ui->checkTunMode->isChecked()) {
        // 禁用按钮防止重复点击
        ui->checkSystemProxy->setEnabled(false);
        
        if (checked) {
            systemProxy->enable(coreProcess->getListenAddr());
            appendLog("✅ 系统代理已启用");
        } else {
            systemProxy->disable();
            appendLog("⏹️ 系统代理已禁用");
        }
        
        // 重新启用按钮
        ui->checkSystemProxy->setEnabled(true);
    }
}

void MainWindow::onTunModeToggled(bool checked)
{
    if (checked) {
        ui->checkSystemProxy->setEnabled(false);
        ui->checkSystemProxy->setChecked(false);
    } else {
        ui->checkSystemProxy->setEnabled(true);
    }
}

void MainWindow::showNodeContextMenu(const QPoint &pos)
{
    QMenu menu(this);
    
    menu.addAction("添加节点", this, &MainWindow::onAddNode);
    
    if (ui->nodeTable->currentRow() >= 0) {
        menu.addAction("编辑节点", this, &MainWindow::onEditNode);
        menu.addAction("删除节点", this, &MainWindow::onDeleteNode);
        menu.addAction("复制节点", this, &MainWindow::onDuplicateNode);
        menu.addSeparator();
        menu.addAction("测试延迟", this, &MainWindow::onTestSelected);
        menu.addSeparator();
        menu.addAction("复制分享链接", this, &MainWindow::onExportToClipboard);
    }
    
    menu.exec(ui->nodeTable->mapToGlobal(pos));
}

void MainWindow::onTrayIconActivated(QSystemTrayIcon::ActivationReason reason)
{
    if (reason == QSystemTrayIcon::DoubleClick) {
        show();
        raise();
        activateWindow();
    }
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    // 检查系统托盘是否可用
    if (trayIcon && QSystemTrayIcon::isSystemTrayAvailable() && trayIcon->isVisible()) {
        hide();
        trayIcon->showMessage("EWP GUI", "程序已最小化到系统托盘", 
            QSystemTrayIcon::Information, 2000);
        event->ignore();
    } else {
        // 没有托盘支持时直接退出
        event->accept();
    }
}

void MainWindow::loadSettings()
{
    QSettings settings("EWP", "EWP-GUI");
    
    restoreGeometry(settings.value("geometry").toByteArray());
    restoreState(settings.value("windowState").toByteArray());
    
    ui->checkSystemProxy->setChecked(settings.value("systemProxy", false).toBool());
    ui->checkTunMode->setChecked(settings.value("tunMode", false).toBool());
}

void MainWindow::saveSettings()
{
    QSettings settings("EWP", "EWP-GUI");
    
    settings.setValue("geometry", saveGeometry());
    settings.setValue("windowState", saveState());
    settings.setValue("systemProxy", ui->checkSystemProxy->isChecked());
    settings.setValue("tunMode", ui->checkTunMode->isChecked());
}
