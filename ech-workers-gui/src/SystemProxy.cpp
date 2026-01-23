#include "SystemProxy.h"
#include <QDebug>

#ifdef Q_OS_WIN
#include <windows.h>
#include <wininet.h>
#endif

SystemProxy::SystemProxy(QObject *parent)
    : QObject(parent)
{
}

SystemProxy::~SystemProxy()
{
    if (enabled) {
        disable();
    }
}

bool SystemProxy::enable(const QString &proxyAddr)
{
#ifdef Q_OS_WIN
    INTERNET_PER_CONN_OPTION_LIST list;
    INTERNET_PER_CONN_OPTION options[3];
    DWORD nSize = sizeof(INTERNET_PER_CONN_OPTION_LIST);
    
    std::wstring proxyWStr = proxyAddr.toStdWString();
    std::wstring bypassWStr = L"localhost;127.*;10.*;172.16.*;192.168.*;<local>";
    
    options[0].dwOption = INTERNET_PER_CONN_FLAGS;
    options[0].Value.dwValue = PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY;
    
    options[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
    options[1].Value.pszValue = const_cast<LPWSTR>(proxyWStr.c_str());
    
    options[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
    options[2].Value.pszValue = const_cast<LPWSTR>(bypassWStr.c_str());
    
    list.dwSize = sizeof(INTERNET_PER_CONN_OPTION_LIST);
    list.pszConnection = NULL;
    list.dwOptionCount = 3;
    list.dwOptionError = 0;
    list.pOptions = options;
    
    if (!InternetSetOptionW(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, nSize)) {
        qWarning() << "设置系统代理失败";
        return false;
    }
    
    InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
    InternetSetOptionW(NULL, INTERNET_OPTION_REFRESH, NULL, 0);
    
    enabled = true;
    currentProxy = proxyAddr;
    qDebug() << "系统代理已启用:" << proxyAddr;
    return true;
#else
    Q_UNUSED(proxyAddr)
    qWarning() << "系统代理设置仅支持 Windows";
    return false;
#endif
}

void SystemProxy::disable()
{
#ifdef Q_OS_WIN
    INTERNET_PER_CONN_OPTION_LIST list;
    INTERNET_PER_CONN_OPTION options[1];
    DWORD nSize = sizeof(INTERNET_PER_CONN_OPTION_LIST);
    
    options[0].dwOption = INTERNET_PER_CONN_FLAGS;
    options[0].Value.dwValue = PROXY_TYPE_DIRECT;
    
    list.dwSize = sizeof(INTERNET_PER_CONN_OPTION_LIST);
    list.pszConnection = NULL;
    list.dwOptionCount = 1;
    list.dwOptionError = 0;
    list.pOptions = options;
    
    InternetSetOptionW(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, nSize);
    InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
    InternetSetOptionW(NULL, INTERNET_OPTION_REFRESH, NULL, 0);
    
    enabled = false;
    currentProxy.clear();
    qDebug() << "系统代理已禁用";
#endif
}
