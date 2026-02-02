package com.echworkers.android.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.echworkers.android.data.AppRepository
import com.echworkers.android.data.NodeRepository
import com.echworkers.android.data.VpnRepository
import com.echworkers.android.model.EWPNode
import com.echworkers.android.model.ProxyMode
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class MainViewModel(application: Application) : AndroidViewModel(application) {
    
    private val nodeRepository = NodeRepository(application)
    private val vpnRepository = VpnRepository(application)
    private val appRepository = AppRepository(application)
    
    val nodes = nodeRepository.nodes.stateIn(
        viewModelScope,
        SharingStarted.WhileSubscribed(5000),
        emptyList()
    )
    
    val selectedNode = nodeRepository.selectedNode.stateIn(
        viewModelScope,
        SharingStarted.WhileSubscribed(5000),
        null
    )
    
    val vpnState = vpnRepository.state.stateIn(
        viewModelScope,
        SharingStarted.WhileSubscribed(5000),
        com.echworkers.android.model.VpnState.Disconnected
    )
    
    val proxyConfig = appRepository.proxyConfig.stateIn(
        viewModelScope,
        SharingStarted.WhileSubscribed(5000),
        com.echworkers.android.model.ProxyConfig()
    )
    
    val installedApps = appRepository.installedApps.stateIn(
        viewModelScope,
        SharingStarted.WhileSubscribed(5000),
        emptyList()
    )
    
    val isLoadingApps = appRepository.isLoading.stateIn(
        viewModelScope,
        SharingStarted.WhileSubscribed(5000),
        false
    )
    
    init {
        loadApps()
    }
    
    fun addNode(node: EWPNode) {
        nodeRepository.addNode(node)
    }
    
    fun updateNode(node: EWPNode) {
        nodeRepository.updateNode(node)
    }
    
    fun deleteNode(nodeId: String) {
        nodeRepository.deleteNode(nodeId)
    }
    
    fun selectNode(nodeId: String) {
        nodeRepository.selectNode(nodeId)
    }
    
    fun connect() {
        selectedNode.value?.let { node ->
            vpnRepository.connect(node, proxyConfig.value)
        }
    }
    
    fun disconnect() {
        vpnRepository.disconnect()
    }
    
    fun setProxyMode(mode: ProxyMode) {
        appRepository.setProxyMode(mode)
    }
    
    fun toggleAppSelection(packageName: String) {
        appRepository.toggleAppSelection(packageName)
    }
    
    fun isAppSelected(packageName: String): Boolean {
        return appRepository.isAppSelected(packageName)
    }
    
    fun clearSelectedApps() {
        appRepository.clearSelectedApps()
    }
    
    fun loadApps() {
        viewModelScope.launch {
            appRepository.loadInstalledApps()
        }
    }
    
    override fun onCleared() {
        super.onCleared()
        vpnRepository.unregister()
    }
}
