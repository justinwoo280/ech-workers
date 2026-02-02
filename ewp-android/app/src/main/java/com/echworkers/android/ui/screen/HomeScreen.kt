package com.echworkers.android.ui.screen

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.echworkers.android.model.EWPNode
import com.echworkers.android.model.VpnState
import com.echworkers.android.ui.theme.SuccessColor
import com.echworkers.android.ui.theme.WarningColor
import com.echworkers.android.viewmodel.MainViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    viewModel: MainViewModel,
    onNavigateToNodeEdit: (String) -> Unit,
    onNavigateToAppSelect: () -> Unit,
    onRequestVpnPermission: () -> Unit
) {
    val nodes by viewModel.nodes.collectAsState()
    val selectedNode by viewModel.selectedNode.collectAsState()
    val vpnState by viewModel.vpnState.collectAsState()
    val proxyConfig by viewModel.proxyConfig.collectAsState()
    
    var showDeleteDialog by remember { mutableStateOf<String?>(null) }
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("EWP VPN") },
                actions = {
                    IconButton(onClick = { onNavigateToAppSelect() }) {
                        Badge(
                            containerColor = if (proxyConfig.selectedPackages.isNotEmpty()) 
                                MaterialTheme.colorScheme.primary 
                            else 
                                MaterialTheme.colorScheme.surfaceVariant
                        ) {
                            if (proxyConfig.selectedPackages.isNotEmpty()) {
                                Text(proxyConfig.selectedPackages.size.toString())
                            }
                        }
                        Icon(
                            Icons.Default.Apps,
                            contentDescription = "应用代理"
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer
                )
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = { onNavigateToNodeEdit("new") }
            ) {
                Icon(Icons.Default.Add, "添加节点")
            }
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            ConnectionCard(
                selectedNode = selectedNode,
                vpnState = vpnState,
                proxyMode = proxyConfig.mode,
                onConnect = onRequestVpnPermission,
                onDisconnect = { viewModel.disconnect() },
                modifier = Modifier.padding(16.dp)
            )
            
            Divider()
            
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .weight(1f),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                items(
                    items = nodes,
                    key = { it.id }
                ) { node ->
                    NodeCard(
                        node = node,
                        isSelected = node.id == selectedNode?.id,
                        isConnected = vpnState.isActive(),
                        onSelect = { viewModel.selectNode(node.id) },
                        onEdit = { onNavigateToNodeEdit(node.id) },
                        onDelete = { showDeleteDialog = node.id }
                    )
                }
                
                if (nodes.isEmpty()) {
                    item {
                        EmptyState()
                    }
                }
            }
        }
    }
    
    showDeleteDialog?.let { nodeId ->
        AlertDialog(
            onDismissRequest = { showDeleteDialog = null },
            title = { Text("删除节点") },
            text = { Text("确定要删除这个节点吗？") },
            confirmButton = {
                TextButton(
                    onClick = {
                        viewModel.deleteNode(nodeId)
                        showDeleteDialog = null
                    }
                ) {
                    Text("删除")
                }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteDialog = null }) {
                    Text("取消")
                }
            }
        )
    }
}

@Composable
private fun ConnectionCard(
    selectedNode: EWPNode?,
    vpnState: VpnState,
    proxyMode: com.echworkers.android.model.ProxyMode,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = when (vpnState) {
                is VpnState.Connected -> SuccessColor.copy(alpha = 0.1f)
                is VpnState.Error -> MaterialTheme.colorScheme.errorContainer
                else -> MaterialTheme.colorScheme.surface
            }
        )
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = when (vpnState) {
                            VpnState.Disconnected -> "未连接"
                            VpnState.Connecting -> "连接中..."
                            is VpnState.Connected -> "已连接"
                            VpnState.Disconnecting -> "断开中..."
                            is VpnState.Error -> "连接失败"
                        },
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold
                    )
                    
                    if (selectedNode != null) {
                        Text(
                            text = selectedNode.name,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                
                StatusIcon(vpnState)
            }
            
            if (vpnState is VpnState.Connected) {
                Divider()
                StatsDisplay(vpnState.stats)
            }
            
            if (vpnState is VpnState.Error) {
                Text(
                    text = vpnState.message,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
            }
            
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Button(
                    onClick = if (vpnState.isActive()) onDisconnect else onConnect,
                    modifier = Modifier.weight(1f),
                    enabled = selectedNode != null && 
                             vpnState !is VpnState.Connecting && 
                             vpnState !is VpnState.Disconnecting,
                    colors = if (vpnState.isActive()) {
                        ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.error
                        )
                    } else {
                        ButtonDefaults.buttonColors()
                    }
                ) {
                    Icon(
                        if (vpnState.isActive()) Icons.Default.Close else Icons.Default.PlayArrow,
                        contentDescription = null,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(if (vpnState.isActive()) "断开" else "连接")
                }
                
                OutlinedButton(
                    onClick = { },
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(
                        Icons.Default.Settings,
                        contentDescription = null,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(proxyMode.displayName())
                }
            }
        }
    }
}

@Composable
private fun StatusIcon(vpnState: VpnState) {
    when (vpnState) {
        is VpnState.Connected -> {
            Icon(
                Icons.Default.CheckCircle,
                contentDescription = "已连接",
                tint = SuccessColor,
                modifier = Modifier.size(48.dp)
            )
        }
        VpnState.Connecting, VpnState.Disconnecting -> {
            CircularProgressIndicator(
                modifier = Modifier.size(48.dp)
            )
        }
        is VpnState.Error -> {
            Icon(
                Icons.Default.Error,
                contentDescription = "错误",
                tint = MaterialTheme.colorScheme.error,
                modifier = Modifier.size(48.dp)
            )
        }
        else -> {
            Icon(
                Icons.Default.Circle,
                contentDescription = "未连接",
                tint = MaterialTheme.colorScheme.surfaceVariant,
                modifier = Modifier.size(48.dp)
            )
        }
    }
}

@Composable
private fun StatsDisplay(stats: com.echworkers.android.model.VpnStats) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            StatItem("运行时间", stats.formatUptime())
            StatItem("连接数", stats.connections.toString())
        }
        
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            StatItem("上传", stats.formatBytes(stats.bytesUp))
            StatItem("下载", stats.formatBytes(stats.bytesDown))
        }
    }
}

@Composable
private fun StatItem(label: String, value: String) {
    Column {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.SemiBold
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun NodeCard(
    node: EWPNode,
    isSelected: Boolean,
    isConnected: Boolean,
    onSelect: () -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit
) {
    Card(
        onClick = if (!isConnected) onSelect else {},
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = if (isSelected) 
                MaterialTheme.colorScheme.primaryContainer 
            else 
                MaterialTheme.colorScheme.surface
        ),
        border = if (isSelected) 
            CardDefaults.outlinedCardBorder() 
        else null
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = node.name,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
                
                Spacer(Modifier.height(4.dp))
                
                Text(
                    text = node.displayType(),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary
                )
                
                Text(
                    text = node.displayAddress(),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                
                if (node.latency > 0) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        Icon(
                            Icons.Default.NetworkCheck,
                            contentDescription = null,
                            modifier = Modifier.size(14.dp),
                            tint = SuccessColor
                        )
                        Text(
                            text = node.displayLatency(),
                            style = MaterialTheme.typography.labelSmall,
                            color = SuccessColor
                        )
                    }
                }
            }
            
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                IconButton(onClick = onEdit, enabled = !isConnected) {
                    Icon(Icons.Default.Edit, "编辑")
                }
                
                IconButton(onClick = onDelete, enabled = !isConnected) {
                    Icon(
                        Icons.Default.Delete,
                        "删除",
                        tint = MaterialTheme.colorScheme.error
                    )
                }
            }
        }
    }
}

@Composable
private fun EmptyState() {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Icon(
            Icons.Default.CloudOff,
            contentDescription = null,
            modifier = Modifier.size(72.dp),
            tint = MaterialTheme.colorScheme.surfaceVariant
        )
        
        Spacer(Modifier.height(16.dp))
        
        Text(
            text = "暂无节点",
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        
        Text(
            text = "点击右下角添加按钮创建第一个节点",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
