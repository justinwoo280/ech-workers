#include "NodeManager.h"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonArray>
#include <QDebug>

NodeManager::NodeManager(QObject *parent)
    : QObject(parent)
{
    QString appDir = QCoreApplication::applicationDirPath();
    configPath = appDir + "/nodes.json";
    load();
}

NodeManager::~NodeManager()
{
    save();
}

void NodeManager::addNode(EWPNode &node)
{
    node.id = nextId++;
    nodes.append(node);
    save();
    emit nodesChanged();
}

void NodeManager::removeNode(int id)
{
    for (int i = 0; i < nodes.size(); ++i) {
        if (nodes[i].id == id) {
            nodes.removeAt(i);
            save();
            emit nodesChanged();
            return;
        }
    }
}

void NodeManager::updateNode(const EWPNode &node)
{
    for (int i = 0; i < nodes.size(); ++i) {
        if (nodes[i].id == node.id) {
            nodes[i] = node;
            save();
            emit nodesChanged();
            return;
        }
    }
}

void NodeManager::updateLatency(int id, int latency)
{
    for (int i = 0; i < nodes.size(); ++i) {
        if (nodes[i].id == id) {
            nodes[i].latency = latency;
            emit nodesChanged();
            return;
        }
    }
}

EWPNode NodeManager::getNode(int id) const
{
    for (const auto &node : nodes) {
        if (node.id == id) {
            return node;
        }
    }
    return EWPNode();
}

void NodeManager::save()
{
    QJsonArray arr;
    for (const auto &node : nodes) {
        arr.append(node.toJson());
    }
    
    QJsonObject root;
    root["nextId"] = nextId;
    root["nodes"] = arr;
    
    QFile file(configPath);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(QJsonDocument(root).toJson());
        file.close();
    }
}

void NodeManager::load()
{
    QFile file(configPath);
    if (!file.open(QIODevice::ReadOnly)) {
        return;
    }
    
    QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    file.close();
    
    if (!doc.isObject()) return;
    
    QJsonObject root = doc.object();
    nextId = root["nextId"].toInt(1);
    
    QJsonArray arr = root["nodes"].toArray();
    nodes.clear();
    for (const auto &val : arr) {
        nodes.append(EWPNode::fromJson(val.toObject()));
    }
}
