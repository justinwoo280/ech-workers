#pragma once

#include <QDialog>
#include "EWPNode.h"

QT_BEGIN_NAMESPACE
namespace Ui { class EditNodeDialog; }
QT_END_NAMESPACE

class EditNodeDialog : public QDialog
{
    Q_OBJECT

public:
    explicit EditNodeDialog(QWidget *parent = nullptr);
    ~EditNodeDialog();

    void setNode(const EWPNode &node);
    EWPNode getNode() const;

private slots:
    void onTransportModeChanged(int index);
    void onEnableECHToggled(bool checked);
    void onGenerateUUID();

private:
    void updateVisibility();
    
    Ui::EditNode *ui;
    EWPNode currentNode;
};
