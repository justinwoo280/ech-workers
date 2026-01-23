#pragma once

#include <QObject>
#include <QString>

class SystemProxy : public QObject
{
    Q_OBJECT

public:
    explicit SystemProxy(QObject *parent = nullptr);
    ~SystemProxy();

    bool enable(const QString &proxyAddr);
    void disable();
    bool isEnabled() const { return enabled; }

private:
    bool enabled = false;
    QString currentProxy;
};
