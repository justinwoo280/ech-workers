#include "EditNodeDialog.h"
#include "ui_EditNodeDialog.h"

#include <QUuid>

EditNodeDialog::EditNodeDialog(QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::EditNodeDialog)
{
    ui->setupUi(this);

    setWindowTitle("编辑节点");

    connect(ui->comboTransport, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &EditNodeDialog::onTransportModeChanged);
    connect(ui->comboProtocol, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &EditNodeDialog::onProtocolChanged);
    connect(ui->checkEnableECH, &QCheckBox::toggled,
            this, &EditNodeDialog::onEnableECHToggled);
    connect(ui->checkEnableTLS, &QCheckBox::toggled,
            this, &EditNodeDialog::onEnableTLSToggled);
    connect(ui->btnGenerateUUID, &QPushButton::clicked,
            this, &EditNodeDialog::onGenerateUUID);

    updateVisibility();
}

EditNodeDialog::~EditNodeDialog()
{
    delete ui;
}

void EditNodeDialog::setNode(const EWPNode &node)
{
    currentNode = node;

    ui->editName->setText(node.name);
    ui->editAddress->setText(node.serverIP);
    ui->spinPort->setValue(node.serverPort);

    ui->comboProtocol->setCurrentIndex(static_cast<int>(node.appProtocol));

    ui->editUUID->setText(node.uuid);
    ui->editTrojanPassword->setText(node.trojanPassword);

    ui->comboTransport->setCurrentIndex(static_cast<int>(node.transportMode));
    ui->editHost->setText(node.serverAddress);

    ui->editWsPath->setText(node.wsPath);

    ui->editGrpcService->setText(node.grpcServiceName);
    ui->editUserAgent->setText(node.userAgent);
    ui->editContentType->setText(node.contentType);

    int xhttpModeIndex = 0;
    if (node.xhttpMode == "stream-one") xhttpModeIndex = 1;
    else if (node.xhttpMode == "stream-down") xhttpModeIndex = 2;
    ui->comboXHTTPMode->setCurrentIndex(xhttpModeIndex);
    ui->editXHTTPPath->setText(node.xhttpPath);

    ui->checkEnableTLS->setChecked(node.enableTLS);
    ui->editSNI->setText(node.sni);
    ui->comboMinTLSVersion->setCurrentIndex(node.minTLSVersion == "1.3" ? 1 : 0);

    ui->checkEnablePQC->setChecked(node.enablePQC);

    ui->checkEnableECH->setChecked(node.enableECH);
    ui->editECHDomain->setText(node.echDomain);
    ui->editDNS->setText(node.dnsServer);

    ui->checkEnableFlow->setChecked(node.enableFlow);

    updateVisibility();
}

EWPNode EditNodeDialog::getNode() const
{
    EWPNode node = currentNode;

    node.name = ui->editName->text().trimmed();
    node.serverIP = ui->editAddress->text().trimmed();
    node.serverPort = ui->spinPort->value();
    node.serverAddress = ui->editHost->text().trimmed();

    node.appProtocol = static_cast<EWPNode::AppProtocol>(ui->comboProtocol->currentIndex());

    node.uuid = ui->editUUID->text().trimmed();
    node.trojanPassword = ui->editTrojanPassword->text().trimmed();

    node.transportMode = static_cast<EWPNode::TransportMode>(ui->comboTransport->currentIndex());

    node.wsPath = ui->editWsPath->text().trimmed();
    if (node.wsPath.isEmpty()) node.wsPath = "/";

    node.grpcServiceName = ui->editGrpcService->text().trimmed();
    if (node.grpcServiceName.isEmpty()) node.grpcServiceName = "ProxyService";
    node.userAgent = ui->editUserAgent->text().trimmed();
    node.contentType = ui->editContentType->text().trimmed();

    switch (ui->comboXHTTPMode->currentIndex()) {
        case 1: node.xhttpMode = "stream-one"; break;
        case 2: node.xhttpMode = "stream-down"; break;
        default: node.xhttpMode = "auto"; break;
    }
    node.xhttpPath = ui->editXHTTPPath->text().trimmed();
    if (node.xhttpPath.isEmpty()) node.xhttpPath = "/xhttp";

    node.enableTLS = ui->checkEnableTLS->isChecked();
    node.sni = ui->editSNI->text().trimmed();
    node.minTLSVersion = (ui->comboMinTLSVersion->currentIndex() == 1) ? "1.3" : "1.2";

    node.enablePQC = ui->checkEnablePQC->isChecked();

    node.enableECH = ui->checkEnableECH->isChecked();
    node.echDomain = ui->editECHDomain->text().trimmed();
    node.dnsServer = ui->editDNS->text().trimmed();

    node.enableFlow = ui->checkEnableFlow->isChecked();

    return node;
}

void EditNodeDialog::onTransportModeChanged(int index)
{
    Q_UNUSED(index)
    updateVisibility();
}

void EditNodeDialog::onProtocolChanged(int index)
{
    Q_UNUSED(index)
    updateVisibility();
}

void EditNodeDialog::onEnableECHToggled(bool checked)
{
    ui->editECHDomain->setEnabled(checked);
    ui->editDNS->setEnabled(checked);

    if (checked) {
        ui->comboMinTLSVersion->setCurrentIndex(1);
        ui->comboMinTLSVersion->setEnabled(false);
    } else {
        ui->comboMinTLSVersion->setEnabled(true);
    }
}

void EditNodeDialog::onEnableTLSToggled(bool checked)
{
    ui->editSNI->setEnabled(checked);
    ui->comboMinTLSVersion->setEnabled(checked && !ui->checkEnableECH->isChecked());
    ui->checkEnablePQC->setEnabled(checked);
    ui->checkEnableECH->setEnabled(checked);
    ui->editECHDomain->setEnabled(checked && ui->checkEnableECH->isChecked());
    ui->editDNS->setEnabled(checked && ui->checkEnableECH->isChecked());
}

void EditNodeDialog::onGenerateUUID()
{
    ui->editUUID->setText(QUuid::createUuid().toString(QUuid::WithoutBraces));
}

void EditNodeDialog::updateVisibility()
{
    int mode = ui->comboTransport->currentIndex();
    int protocol = ui->comboProtocol->currentIndex();
    bool isTrojan = (protocol == EWPNode::TROJAN);
    bool tlsEnabled = ui->checkEnableTLS->isChecked();
    bool echEnabled = ui->checkEnableECH->isChecked();

    ui->labelUUID->setVisible(!isTrojan);
    ui->editUUID->setVisible(!isTrojan);
    ui->btnGenerateUUID->setVisible(!isTrojan);
    ui->labelTrojanPassword->setVisible(isTrojan);
    ui->editTrojanPassword->setVisible(isTrojan);

    ui->advancedGroup->setVisible(!isTrojan);

    ui->wsGroup->setVisible(mode == EWPNode::WS);
    ui->grpcGroup->setVisible(mode == EWPNode::GRPC || mode == EWPNode::H3GRPC);
    ui->labelContentType->setVisible(mode == EWPNode::H3GRPC);
    ui->editContentType->setVisible(mode == EWPNode::H3GRPC);
    ui->xhttpGroup->setVisible(mode == EWPNode::XHTTP);

    ui->editSNI->setEnabled(tlsEnabled);
    ui->checkEnablePQC->setEnabled(tlsEnabled);
    ui->checkEnableECH->setEnabled(tlsEnabled);
    ui->editECHDomain->setEnabled(tlsEnabled && echEnabled);
    ui->editDNS->setEnabled(tlsEnabled && echEnabled);
    ui->comboMinTLSVersion->setEnabled(tlsEnabled && !echEnabled);

    if (tlsEnabled && echEnabled) {
        ui->comboMinTLSVersion->setCurrentIndex(1);
    }

    adjustSize();
}
