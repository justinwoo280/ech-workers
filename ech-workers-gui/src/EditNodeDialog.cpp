#include "EditNodeDialog.h"
#include "ui_EditNodeDialog.h"

#include <QUuid>

EditNodeDialog::EditNodeDialog(QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::EditNodeDialog)
{
    ui->setupUi(this);
    
    setWindowTitle("编辑节点");
    
    // 连接信号
    connect(ui->comboTransport, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &EditNodeDialog::onTransportModeChanged);
    connect(ui->checkEnableECH, &QCheckBox::toggled,
            this, &EditNodeDialog::onEnableECHToggled);
    
    // 初始化可见性
    updateVisibility();
}

EditNodeDialog::~EditNodeDialog()
{
    delete ui;
}

void EditNodeDialog::setNode(const EWPNode &node)
{
    currentNode = node;
    
    // 基本配置
    ui->editName->setText(node.name);
    ui->editAddress->setText(node.serverAddress);
    ui->spinPort->setValue(node.serverPort);
    ui->editUUID->setText(node.uuid);
    ui->editServerIP->setText(node.serverIP);
    
    // 传输协议
    ui->comboTransport->setCurrentIndex(static_cast<int>(node.transportMode));
    
    // WebSocket 配置
    ui->editWsPath->setText(node.wsPath);
    
    // gRPC 配置
    ui->editGrpcService->setText(node.grpcServiceName);
    
    // ECH 配置
    ui->checkEnableECH->setChecked(node.enableECH);
    ui->editECHDomain->setText(node.echDomain);
    ui->editDNS->setText(node.dnsServer);
    
    // 高级配置
    ui->checkEnableFlow->setChecked(node.enableFlow);
    ui->checkEnablePQC->setChecked(node.enablePQC);
    
    // XHTTP 配置
    int xhttpModeIndex = 0;
    if (node.xhttpMode == "stream-one") xhttpModeIndex = 1;
    else if (node.xhttpMode == "stream-down") xhttpModeIndex = 2;
    ui->comboXHTTPMode->setCurrentIndex(xhttpModeIndex);
    ui->editXHTTPPath->setText(node.xhttpPath);
    
    updateVisibility();
}

EWPNode EditNodeDialog::getNode() const
{
    EWPNode node = currentNode;
    
    // 基本配置
    node.name = ui->editName->text().trimmed();
    node.serverAddress = ui->editAddress->text().trimmed();
    node.serverPort = ui->spinPort->value();
    node.uuid = ui->editUUID->text().trimmed();
    node.serverIP = ui->editServerIP->text().trimmed();
    
    // 传输协议
    node.transportMode = static_cast<EWPNode::TransportMode>(ui->comboTransport->currentIndex());
    
    // WebSocket 配置
    node.wsPath = ui->editWsPath->text().trimmed();
    if (node.wsPath.isEmpty()) node.wsPath = "/";
    
    // gRPC 配置
    node.grpcServiceName = ui->editGrpcService->text().trimmed();
    if (node.grpcServiceName.isEmpty()) node.grpcServiceName = "ProxyService";
    
    // ECH 配置
    node.enableECH = ui->checkEnableECH->isChecked();
    node.echDomain = ui->editECHDomain->text().trimmed();
    node.dnsServer = ui->editDNS->text().trimmed();
    
    // 高级配置
    node.enableFlow = ui->checkEnableFlow->isChecked();
    node.enablePQC = ui->checkEnablePQC->isChecked();
    
    // XHTTP 配置
    switch (ui->comboXHTTPMode->currentIndex()) {
        case 1: node.xhttpMode = "stream-one"; break;
        case 2: node.xhttpMode = "stream-down"; break;
        default: node.xhttpMode = "auto"; break;
    }
    node.xhttpPath = ui->editXHTTPPath->text().trimmed();
    if (node.xhttpPath.isEmpty()) node.xhttpPath = "/xhttp";
    
    return node;
}

void EditNodeDialog::onTransportModeChanged(int index)
{
    Q_UNUSED(index)
    updateVisibility();
}

void EditNodeDialog::onEnableECHToggled(bool checked)
{
    ui->editECHDomain->setEnabled(checked);
    ui->editDNS->setEnabled(checked);
}

void EditNodeDialog::onGenerateUUID()
{
    ui->editUUID->setText(QUuid::createUuid().toString(QUuid::WithoutBraces));
}

void EditNodeDialog::updateVisibility()
{
    int mode = ui->comboTransport->currentIndex();
    
    // WebSocket 配置组
    ui->wsGroup->setVisible(mode == EWPNode::WS);
    
    // gRPC 配置组
    ui->grpcGroup->setVisible(mode == EWPNode::GRPC);
    
    // XHTTP 配置组
    ui->xhttpGroup->setVisible(mode == EWPNode::XHTTP);
    
    // ECH 相关控件
    bool echEnabled = ui->checkEnableECH->isChecked();
    ui->editECHDomain->setEnabled(echEnabled);
    ui->editDNS->setEnabled(echEnabled);
    ui->checkEnablePQC->setEnabled(echEnabled);
    
    // 调整对话框大小
    adjustSize();
}
