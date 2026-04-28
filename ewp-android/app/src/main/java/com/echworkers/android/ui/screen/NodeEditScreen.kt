package com.echworkers.android.ui.screen

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.echworkers.android.model.EWPNode
import com.echworkers.android.viewmodel.MainViewModel

/**
 * v2 node editor.
 *
 * The 12 v1 fields (appProtocol, password, xhttpMode, userAgent,
 * contentType, enableTLS, minTLSVersion, echDomain, dnsServer,
 * enableFlow, enablePQC, enableMozillaCA) are gone — v2 mandates
 * EWP + TLS 1.3 + ML-KEM-768 + Mozilla CA + ECH-when-available
 * with no opt-out. Less surface = fewer ways for users to weaken
 * their own security.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NodeEditScreen(
    viewModel: MainViewModel,
    nodeId: String?,
    onNavigateBack: () -> Unit,
) {
    val existingNode = nodeId?.let { id ->
        viewModel.nodes.collectAsState().value.find { it.id == id }
    }

    var name by remember { mutableStateOf(existingNode?.name ?: "") }
    var serverAddress by remember { mutableStateOf(existingNode?.serverAddress ?: "") }
    var serverPort by remember { mutableStateOf(existingNode?.serverPort?.toString() ?: "443") }
    var host by remember { mutableStateOf(existingNode?.host ?: "") }
    var sni by remember { mutableStateOf(existingNode?.sni ?: "") }

    var uuid by remember { mutableStateOf(existingNode?.uuid ?: "") }

    var transportMode by remember { mutableStateOf(existingNode?.transportMode ?: EWPNode.TransportMode.WS) }
    var wsPath by remember { mutableStateOf(existingNode?.wsPath ?: "/ewp") }
    var grpcServiceName by remember { mutableStateOf(existingNode?.grpcServiceName ?: "ProxyService") }
    var xhttpPath by remember { mutableStateOf(existingNode?.xhttpPath ?: "/xhttp") }

    var enableECH by remember { mutableStateOf(existingNode?.enableECH ?: true) }
    var echDomain by remember { mutableStateOf(existingNode?.echDomain ?: "") }
    var dohServers by remember { mutableStateOf(existingNode?.dohServers ?: "") }

    val canSave = name.isNotBlank() &&
        serverAddress.isNotBlank() &&
        uuid.isNotBlank()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (existingNode == null) "新建节点" else "编辑节点") },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "返回")
                    }
                },
                actions = {
                    TextButton(
                        enabled = canSave,
                        onClick = {
                            val node = EWPNode(
                                id = existingNode?.id ?: java.util.UUID.randomUUID().toString(),
                                name = name,
                                serverAddress = serverAddress,
                                serverPort = serverPort.toIntOrNull() ?: 443,
                                uuid = uuid,
                                transportMode = transportMode,
                                wsPath = wsPath,
                                grpcServiceName = grpcServiceName,
                                xhttpPath = xhttpPath,
                                host = host,
                                sni = sni,
                                enableECH = enableECH,
                                echDomain = echDomain.trim(),
                                dohServers = dohServers,
                            )
                            if (existingNode == null) {
                                viewModel.addNode(node)
                            } else {
                                viewModel.updateNode(node)
                            }
                            onNavigateBack()
                        },
                    ) { Text("保存") }
                },
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            // ---------- 基本 ----------
            Text("基本", style = MaterialTheme.typography.titleSmall)
            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text("名称") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = serverAddress,
                    onValueChange = { serverAddress = it },
                    label = { Text("服务器地址") },
                    modifier = Modifier.weight(2f),
                    singleLine = true,
                )
                OutlinedTextField(
                    value = serverPort,
                    onValueChange = { serverPort = it.filter { c -> c.isDigit() }.take(5) },
                    label = { Text("端口") },
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                )
            }
            OutlinedTextField(
                value = host,
                onValueChange = { host = it },
                label = { Text("Host (可选, CDN 场景)") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            OutlinedTextField(
                value = sni,
                onValueChange = { sni = it },
                label = { Text("SNI (可选, 默认同 Host)") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )

            HorizontalDivider()

            // ---------- 认证 ----------
            Text("认证", style = MaterialTheme.typography.titleSmall)
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = uuid,
                    onValueChange = { uuid = it.lowercase() },
                    label = { Text("UUID (32 hex)") },
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                )
                Spacer(Modifier.width(8.dp))
                IconButton(onClick = {
                    uuid = java.util.UUID.randomUUID().toString().replace("-", "")
                }) {
                    Icon(Icons.Default.Refresh, contentDescription = "随机生成")
                }
            }

            HorizontalDivider()

            // ---------- 传输 ----------
            Text("传输", style = MaterialTheme.typography.titleSmall)
            val modes = listOf(
                EWPNode.TransportMode.WS to "WebSocket",
                EWPNode.TransportMode.GRPC to "gRPC",
                EWPNode.TransportMode.XHTTP to "XHTTP",
                EWPNode.TransportMode.H3GRPC to "H3gRPC",
            )
            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                modes.forEachIndexed { idx, (m, label) ->
                    SegmentedButton(
                        selected = transportMode == m,
                        onClick = { transportMode = m },
                        shape = SegmentedButtonDefaults.itemShape(idx, modes.size),
                    ) { Text(label) }
                }
            }
            when (transportMode) {
                EWPNode.TransportMode.WS -> OutlinedTextField(
                    value = wsPath, onValueChange = { wsPath = it },
                    label = { Text("WS 路径") },
                    modifier = Modifier.fillMaxWidth(), singleLine = true,
                )
                EWPNode.TransportMode.GRPC, EWPNode.TransportMode.H3GRPC -> OutlinedTextField(
                    value = grpcServiceName, onValueChange = { grpcServiceName = it },
                    label = { Text("gRPC 服务名") },
                    modifier = Modifier.fillMaxWidth(), singleLine = true,
                )
                EWPNode.TransportMode.XHTTP -> OutlinedTextField(
                    value = xhttpPath, onValueChange = { xhttpPath = it },
                    label = { Text("XHTTP 路径") },
                    modifier = Modifier.fillMaxWidth(), singleLine = true,
                )
            }

            HorizontalDivider()

            // ---------- ECH / DNS ----------
            Text("ECH 与 DNS", style = MaterialTheme.typography.titleSmall)
            ListItem(
                headlineContent = { Text("启用 ECH") },
                supportingContent = { Text("加密 ClientHello,隐藏 SNI") },
                trailingContent = {
                    Switch(checked = enableECH, onCheckedChange = { enableECH = it })
                },
            )
            OutlinedTextField(
                value = echDomain,
                onValueChange = { echDomain = it },
                label = { Text("ECH 查询域名 (可选)") },
                placeholder = { Text("Cloudflare 用户填 cloudflare-ech.com") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                supportingText = { Text("ECH 公钥发布的域名,与 SNI 是两件事。Cloudflare 集中托管 → cloudflare-ech.com;自建 → 留空走 SNI") },
            )
            OutlinedTextField(
                value = dohServers,
                onValueChange = { dohServers = it },
                label = { Text("DoH 服务器 (可选, 逗号分隔)") },
                placeholder = { Text("默认: AliDNS + DNSPod") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = false,
                supportingText = { Text("用于解析服务器域名 + ECH bootstrap. 留空走内置中国友好默认 (223.5.5.5 / 223.6.6.6 / doh.pub)") },
            )

            Spacer(Modifier.height(24.dp))
        }
    }
}
