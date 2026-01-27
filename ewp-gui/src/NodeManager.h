#pragma once

#include <QObject>
#include <QList>
#include "EWPNode.h"

class NodeManager : public QObject
{
    Q_OBJECT

public:
    explicit NodeManager(QObject *parent = nullptr);
    ~NodeManager();

    void addNode(EWPNode &node);
    void removeNode(int id);
    void updateNode(const EWPNode &node);
    void updateLatency(int id, int latency);
    
    EWPNode getNode(int id) const;
    QList<EWPNode> getAllNodes() const { return nodes; }
    int getNodeCount() const { return nodes.size(); }
    
    void save();
    void load();

signals:
    void nodesChanged();

private:
    int nextId = 1;
    QList<EWPNode> nodes;
    QString configPath;
};
