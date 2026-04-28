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
    ui->editAddress->setText(node.server);
    ui->spinPort->setValue(node.serverPort);
    ui->editHost->setText(node.host);
    ui->editSNI->setText(node.sni);

    ui->editUUID->setText(node.uuid);

    ui->comboTransport->setCurrentIndex(static_cast<int>(node.transportMode));

    ui->editWsPath->setText(node.wsPath);
    ui->editGrpcService->setText(node.grpcServiceName);
    ui->editXHTTPPath->setText(node.xhttpPath);

    ui->checkEnableECH->setChecked(node.enableECH);
    ui->editECHDomain->setText(node.echDomain);
    ui->editDoHServers->setText(node.dohServers);

    updateVisibility();
}

EWPNode EditNodeDialog::getNode() const
{
    EWPNode node = currentNode;

    node.name       = ui->editName->text().trimmed();
    node.server     = ui->editAddress->text().trimmed();
    node.serverPort = ui->spinPort->value();
    node.host       = ui->editHost->text().trimmed();
    node.sni        = ui->editSNI->text().trimmed();

    node.uuid = ui->editUUID->text().trimmed();

    node.transportMode = static_cast<EWPNode::TransportMode>(ui->comboTransport->currentIndex());

    node.wsPath = ui->editWsPath->text().trimmed();
    if (node.wsPath.isEmpty()) node.wsPath = "/ewp";

    node.grpcServiceName = ui->editGrpcService->text().trimmed();
    if (node.grpcServiceName.isEmpty()) node.grpcServiceName = "ProxyService";

    node.xhttpPath = ui->editXHTTPPath->text().trimmed();
    if (node.xhttpPath.isEmpty()) node.xhttpPath = "/xhttp";

    node.enableECH  = ui->checkEnableECH->isChecked();
    node.echDomain  = ui->editECHDomain->text().trimmed();
    node.dohServers = ui->editDoHServers->text().trimmed();

    return node;
}

void EditNodeDialog::onTransportModeChanged(int) { updateVisibility(); }

void EditNodeDialog::onGenerateUUID()
{
    ui->editUUID->setText(QUuid::createUuid().toString(QUuid::WithoutBraces).remove('-'));
}

void EditNodeDialog::updateVisibility()
{
    int mode = ui->comboTransport->currentIndex();
    ui->wsGroup->setVisible(mode == EWPNode::WS);
    ui->grpcGroup->setVisible(mode == EWPNode::GRPC || mode == EWPNode::H3GRPC);
    ui->xhttpGroup->setVisible(mode == EWPNode::XHTTP);
    adjustSize();
}
