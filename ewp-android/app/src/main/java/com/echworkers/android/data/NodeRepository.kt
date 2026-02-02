package com.echworkers.android.data

import android.content.Context
import android.util.Log
import com.echworkers.android.model.EWPNode
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class NodeRepository(context: Context) {
    
    companion object {
        private const val TAG = "NodeRepository"
        private const val PREFS_NAME = "nodes"
        private const val KEY_NODES = "nodes_json"
        private const val KEY_SELECTED_NODE_ID = "selected_node_id"
    }
    
    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val json = Json { 
        ignoreUnknownKeys = true
        encodeDefaults = true
    }
    
    private val _nodes = MutableStateFlow<List<EWPNode>>(emptyList())
    val nodes: StateFlow<List<EWPNode>> = _nodes.asStateFlow()
    
    private val _selectedNode = MutableStateFlow<EWPNode?>(null)
    val selectedNode: StateFlow<EWPNode?> = _selectedNode.asStateFlow()
    
    init {
        loadNodes()
    }
    
    fun addNode(node: EWPNode) {
        val updated = _nodes.value + node
        _nodes.value = updated
        saveNodes(updated)
        Log.i(TAG, "Node added: ${node.name}")
    }
    
    fun updateNode(node: EWPNode) {
        val updated = _nodes.value.map { 
            if (it.id == node.id) node else it 
        }
        _nodes.value = updated
        saveNodes(updated)
        
        if (_selectedNode.value?.id == node.id) {
            _selectedNode.value = node
            saveSelectedNodeId(node.id)
        }
        
        Log.i(TAG, "Node updated: ${node.name}")
    }
    
    fun deleteNode(nodeId: String) {
        val updated = _nodes.value.filter { it.id != nodeId }
        _nodes.value = updated
        saveNodes(updated)
        
        if (_selectedNode.value?.id == nodeId) {
            _selectedNode.value = updated.firstOrNull()
            saveSelectedNodeId(_selectedNode.value?.id)
        }
        
        Log.i(TAG, "Node deleted: $nodeId")
    }
    
    fun selectNode(nodeId: String) {
        val node = _nodes.value.find { it.id == nodeId }
        _selectedNode.value = node
        saveSelectedNodeId(nodeId)
        Log.i(TAG, "Node selected: ${node?.name}")
    }
    
    fun getNodeById(nodeId: String): EWPNode? {
        return _nodes.value.find { it.id == nodeId }
    }
    
    private fun saveNodes(nodes: List<EWPNode>) {
        try {
            val jsonString = json.encodeToString(nodes)
            prefs.edit().putString(KEY_NODES, jsonString).apply()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to save nodes", e)
        }
    }
    
    private fun loadNodes() {
        try {
            val jsonString = prefs.getString(KEY_NODES, null)
            if (jsonString != null) {
                val nodes = json.decodeFromString<List<EWPNode>>(jsonString)
                _nodes.value = nodes
                Log.i(TAG, "Loaded ${nodes.size} nodes")
                
                val selectedId = prefs.getString(KEY_SELECTED_NODE_ID, null)
                if (selectedId != null) {
                    _selectedNode.value = nodes.find { it.id == selectedId }
                } else {
                    _selectedNode.value = nodes.firstOrNull()
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load nodes", e)
        }
    }
    
    private fun saveSelectedNodeId(nodeId: String?) {
        prefs.edit().putString(KEY_SELECTED_NODE_ID, nodeId).apply()
    }
}
