package com.echworkers.android.ui.screen

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.echworkers.android.model.EWPNode
import com.echworkers.android.viewmodel.MainViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NodeEditScreen(
    viewModel: MainViewModel,
    nodeId: String?,
    onNavigateBack: () -> Unit
) {
    val existingNode = nodeId?.let { id ->
        viewModel.nodes.collectAsState().value.find { it.id == id }
    }
    
    var name by remember { mutableStateOf(existingNode?.name ?: "") }
    var serverAddress by remember { mutableStateOf(existingNode?.serverAddress ?: "") }
    var serverPort by remember { mutableStateOf(existingNode?.serverPort?.toString() ?: "443") }
    var serverIP by remember { mutableStateOf(existingNode?.serverIP ?: "") }
    
    var appProtocol by remember { mutableStateOf(existingNode?.appProtocol ?: EWPNode.AppProtocol.EWP) }
    var uuid by remember { mutableStateOf(existingNode?.uuid ?: "") }
    var password by remember { mutableStateOf(existingNode?.password ?: "") }
    
    var transportMode by remember { mutableStateOf(existingNode?.transportMode ?: EWPNode.TransportMode.WS) }
    var wsPath by remember { mutableStateOf(existingNode?.wsPath ?: "/") }
    var grpcServiceName by remember { mutableStateOf(existingNode?.grpcServiceName ?: "ProxyService") }
    var xhttpPath by remember { mutableStateOf(existingNode?.xhttpPath ?: "/xhttp") }
    
    var enableECH by remember { mutableStateOf(existingNode?.enableECH ?: true) }
    var echDomain by remember { mutableStateOf(existingNode?.echDomain ?: "cloudflare-ech.com") }
    var dnsServer by remember { mutableStateOf(existingNode?.dnsServer ?: "dns.alidns.com/dns-query") }
    
    var enableFlow by remember { mutableStateOf(existingNode?.enableFlow ?: true) }
    var enablePQC by remember { mutableStateOf(existingNode?.enablePQC ?: false) }
    
    var showAdvanced by remember { mutableStateOf(false) }
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (nodeId == null) "添加节点" else "编辑节点") },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.Default.ArrowBack, "返回")
                    }
                },
                actions = {
                    TextButton(
                        onClick = {
                            val node = EWPNode(
                                id = existingNode?.id ?: "",
                                name = name,
                                serverAddress = serverAddress,
                                serverPort = serverPort.toIntOrNull() ?: 443,
                                serverIP = serverIP,
                                appProtocol = appProtocol,
                                uuid = uuid,
                                password = password,
                                transportMode = transportMode,
                                wsPath = wsPath,
                                grpcServiceName = grpcServiceName,
                                xhttpPath = xhttpPath,
                                enableECH = enableECH,
                                echDomain = echDomain,
                                dnsServer = dnsServer,
                                enableFlow = enableFlow,
                                enablePQC = enablePQC
                            )
                            
                            if (existingNode == null) {
                                viewModel.addNode(node)
                            } else {
                                viewModel.updateNode(node)
                            }
                            
                            onNavigateBack()
                        },
                        enabled = name.isNotBlank() && 
                                 serverAddress.isNotBlank() &&
                                 (appProtocol == EWPNode.AppProtocol.TROJAN && password.isNotBlank() ||
                                  appProtocol == EWPNode.AppProtocol.EWP && uuid.isNotBlank())
                    ) {
                        Text("保存")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text("节点名称") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
            
            OutlinedTextField(
                value = serverAddress,
                onValueChange = { serverAddress = it },
                label = { Text("服务器地址") },
                placeholder = { Text("example.com") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
            
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                OutlinedTextField(
                    value = serverPort,
                    onValueChange = { serverPort = it },
                    label = { Text("端口") },
                    modifier = Modifier.weight(1f),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    singleLine = true
                )
                
                OutlinedTextField(
                    value = serverIP,
                    onValueChange = { serverIP = it },
                    label = { Text("优选 IP (可选)") },
                    modifier = Modifier.weight(2f),
                    singleLine = true
                )
            }
            
            Text(
                text = "协议设置",
                style = MaterialTheme.typography.titleMedium
            )
            
            SegmentedButton(
                options = listOf("EWP", "Trojan"),
                selectedIndex = if (appProtocol == EWPNode.AppProtocol.EWP) 0 else 1,
                onSelectionChange = { index ->
                    appProtocol = if (index == 0) EWPNode.AppProtocol.EWP else EWPNode.AppProtocol.TROJAN
                }
            )
            
            when (appProtocol) {
                EWPNode.AppProtocol.EWP -> {
                    OutlinedTextField(
                        value = uuid,
                        onValueChange = { uuid = it },
                        label = { Text("UUID") },
                        placeholder = { Text("00000000-0000-0000-0000-000000000000") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                }
                EWPNode.AppProtocol.TROJAN -> {
                    OutlinedTextField(
                        value = password,
                        onValueChange = { password = it },
                        label = { Text("密码") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                }
            }
            
            Text(
                text = "传输协议",
                style = MaterialTheme.typography.titleMedium
            )
            
            SegmentedButton(
                options = listOf("WebSocket", "gRPC", "XHTTP"),
                selectedIndex = when (transportMode) {
                    EWPNode.TransportMode.WS -> 0
                    EWPNode.TransportMode.GRPC -> 1
                    EWPNode.TransportMode.XHTTP -> 2
                },
                onSelectionChange = { index ->
                    transportMode = when (index) {
                        0 -> EWPNode.TransportMode.WS
                        1 -> EWPNode.TransportMode.GRPC
                        else -> EWPNode.TransportMode.XHTTP
                    }
                }
            )
            
            when (transportMode) {
                EWPNode.TransportMode.WS -> {
                    OutlinedTextField(
                        value = wsPath,
                        onValueChange = { wsPath = it },
                        label = { Text("WebSocket 路径") },
                        placeholder = { Text("/") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                }
                EWPNode.TransportMode.GRPC -> {
                    OutlinedTextField(
                        value = grpcServiceName,
                        onValueChange = { grpcServiceName = it },
                        label = { Text("gRPC 服务名") },
                        placeholder = { Text("ProxyService") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                }
                EWPNode.TransportMode.XHTTP -> {
                    OutlinedTextField(
                        value = xhttpPath,
                        onValueChange = { xhttpPath = it },
                        label = { Text("XHTTP 路径") },
                        placeholder = { Text("/xhttp") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                }
            }
            
            Divider()
            
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text("启用 ECH", style = MaterialTheme.typography.bodyLarge)
                Switch(checked = enableECH, onCheckedChange = { enableECH = it })
            }
            
            if (enableECH) {
                OutlinedTextField(
                    value = echDomain,
                    onValueChange = { echDomain = it },
                    label = { Text("ECH 域名") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )
                
                OutlinedTextField(
                    value = dnsServer,
                    onValueChange = { dnsServer = it },
                    label = { Text("DNS 服务器") },
                    placeholder = { Text("dns.alidns.com/dns-query") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )
            }
            
            TextButton(
                onClick = { showAdvanced = !showAdvanced }
            ) {
                Text(if (showAdvanced) "隐藏高级选项" else "显示高级选项")
            }
            
            if (showAdvanced) {
                if (appProtocol == EWPNode.AppProtocol.EWP) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text("启用 Vision 流控", style = MaterialTheme.typography.bodyLarge)
                        Switch(checked = enableFlow, onCheckedChange = { enableFlow = it })
                    }
                }
                
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text("启用 PQC", style = MaterialTheme.typography.bodyLarge)
                    Switch(checked = enablePQC, onCheckedChange = { enablePQC = it })
                }
            }
        }
    }
}

@Composable
private fun SegmentedButton(
    options: List<String>,
    selectedIndex: Int,
    onSelectionChange: (Int) -> Unit,
    modifier: Modifier = Modifier
) {
    Row(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        options.forEachIndexed { index, option ->
            FilterChip(
                selected = selectedIndex == index,
                onClick = { onSelectionChange(index) },
                label = { Text(option) },
                modifier = Modifier.weight(1f)
            )
        }
    }
}
