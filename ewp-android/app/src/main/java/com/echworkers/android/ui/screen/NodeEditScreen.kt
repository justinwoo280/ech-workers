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
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.echworkers.android.model.EWPNode
import com.echworkers.android.viewmodel.MainViewModel
import java.util.UUID

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
    var host by remember { mutableStateOf(existingNode?.host ?: "") }

    var appProtocol by remember { mutableStateOf(existingNode?.appProtocol ?: EWPNode.AppProtocol.EWP) }
    var uuid by remember { mutableStateOf(existingNode?.uuid ?: "") }
    var password by remember { mutableStateOf(existingNode?.password ?: "") }

    var transportMode by remember { mutableStateOf(existingNode?.transportMode ?: EWPNode.TransportMode.WS) }
    var wsPath by remember { mutableStateOf(existingNode?.wsPath ?: "/") }
    var grpcServiceName by remember { mutableStateOf(existingNode?.grpcServiceName ?: "ProxyService") }
    var xhttpPath by remember { mutableStateOf(existingNode?.xhttpPath ?: "/xhttp") }
    var xhttpMode by remember { mutableStateOf(existingNode?.xhttpMode ?: "auto") }
    var userAgent by remember { mutableStateOf(existingNode?.userAgent ?: "") }
    var contentType by remember { mutableStateOf(existingNode?.contentType ?: "") }

    var sni by remember { mutableStateOf(existingNode?.sni ?: "") }
    var enableTLS by remember { mutableStateOf(existingNode?.enableTLS ?: true) }
    var minTLSVersion by remember { mutableStateOf(existingNode?.minTLSVersion ?: "1.2") }

    var enableECH by remember { mutableStateOf(existingNode?.enableECH ?: true) }
    var echDomain by remember { mutableStateOf(existingNode?.echDomain ?: "cloudflare-ech.com") }
    var dnsServer by remember { mutableStateOf(existingNode?.dnsServer ?: "dns.alidns.com/dns-query") }

    var enableFlow by remember { mutableStateOf(existingNode?.enableFlow ?: true) }
    var enablePQC by remember { mutableStateOf(existingNode?.enablePQC ?: false) }

    var showAdvanced by remember { mutableStateOf(false) }

    val isValid = name.isNotBlank() && serverAddress.isNotBlank() &&
            (appProtocol == EWPNode.AppProtocol.TROJAN && password.isNotBlank() ||
                    appProtocol == EWPNode.AppProtocol.EWP && uuid.isNotBlank())

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
                                id = existingNode?.id ?: UUID.randomUUID().toString(),
                                name = name,
                                serverAddress = serverAddress,
                                serverPort = serverPort.toIntOrNull() ?: 443,
                                serverIP = serverIP,
                                host = host,
                                appProtocol = appProtocol,
                                uuid = uuid,
                                password = password,
                                transportMode = transportMode,
                                wsPath = wsPath,
                                grpcServiceName = grpcServiceName,
                                xhttpPath = xhttpPath,
                                xhttpMode = xhttpMode,
                                userAgent = userAgent,
                                contentType = contentType,
                                sni = sni,
                                enableTLS = enableTLS,
                                minTLSVersion = minTLSVersion,
                                enableECH = enableECH,
                                echDomain = echDomain,
                                dnsServer = dnsServer,
                                enableFlow = enableFlow,
                                enablePQC = enablePQC
                            )
                            if (existingNode == null) viewModel.addNode(node)
                            else viewModel.updateNode(node)
                            onNavigateBack()
                        },
                        enabled = isValid
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
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            SectionTitle("基本配置")

            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text("名称") },
                placeholder = { Text("节点名称") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutlinedTextField(
                    value = serverAddress,
                    onValueChange = { serverAddress = it },
                    label = { Text("服务器地址") },
                    placeholder = { Text("IP 或域名（实际连接目标）") },
                    modifier = Modifier.weight(1f),
                    singleLine = true
                )
                OutlinedTextField(
                    value = serverPort,
                    onValueChange = { serverPort = it },
                    label = { Text("端口") },
                    modifier = Modifier.width(90.dp),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    singleLine = true
                )
            }

            SegmentedButton(
                label = "应用协议",
                options = listOf("EWP (默认)", "Trojan"),
                selectedIndex = if (appProtocol == EWPNode.AppProtocol.EWP) 0 else 1,
                onSelectionChange = {
                    appProtocol = if (it == 0) EWPNode.AppProtocol.EWP else EWPNode.AppProtocol.TROJAN
                }
            )

            when (appProtocol) {
                EWPNode.AppProtocol.EWP -> {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        OutlinedTextField(
                            value = uuid,
                            onValueChange = { uuid = it },
                            label = { Text("UUID") },
                            placeholder = { Text("EWP 认证令牌") },
                            modifier = Modifier.weight(1f),
                            singleLine = true
                        )
                        IconButton(onClick = { uuid = UUID.randomUUID().toString() }) {
                            Icon(Icons.Default.Refresh, contentDescription = "生成 UUID")
                        }
                    }
                }
                EWPNode.AppProtocol.TROJAN -> {
                    OutlinedTextField(
                        value = password,
                        onValueChange = { password = it },
                        label = { Text("Trojan 密码") },
                        modifier = Modifier.fillMaxWidth(),
                        visualTransformation = PasswordVisualTransformation(),
                        singleLine = true
                    )
                }
            }

            if (appProtocol == EWPNode.AppProtocol.EWP) {
                SwitchRow("Vision 流控", enableFlow) { enableFlow = it }
            }

            Divider()
            SectionTitle("传输配置")

            SegmentedButton(
                label = "传输协议",
                options = listOf("WebSocket", "gRPC", "XHTTP", "H3gRPC"),
                selectedIndex = when (transportMode) {
                    EWPNode.TransportMode.WS -> 0
                    EWPNode.TransportMode.GRPC -> 1
                    EWPNode.TransportMode.XHTTP -> 2
                    EWPNode.TransportMode.H3GRPC -> 3
                },
                onSelectionChange = {
                    transportMode = when (it) {
                        0 -> EWPNode.TransportMode.WS
                        1 -> EWPNode.TransportMode.GRPC
                        2 -> EWPNode.TransportMode.XHTTP
                        else -> EWPNode.TransportMode.H3GRPC
                    }
                }
            )

            OutlinedTextField(
                value = host,
                onValueChange = { host = it },
                label = { Text("Host") },
                placeholder = { Text("留空则同服务器地址（CDN 域名 / HTTP Host 头）") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            when (transportMode) {
                EWPNode.TransportMode.WS -> {
                    OutlinedTextField(
                        value = wsPath,
                        onValueChange = { wsPath = it },
                        label = { Text("路径 (Path)") },
                        placeholder = { Text("/") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                }
                EWPNode.TransportMode.GRPC -> {
                    OutlinedTextField(
                        value = grpcServiceName,
                        onValueChange = { grpcServiceName = it },
                        label = { Text("服务名 (ServiceName)") },
                        placeholder = { Text("ProxyService") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                    OutlinedTextField(
                        value = userAgent,
                        onValueChange = { userAgent = it },
                        label = { Text("User-Agent") },
                        placeholder = { Text("留空使用默认浏览器 UA") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                }
                EWPNode.TransportMode.XHTTP -> {
                    DropdownRow(
                        label = "模式",
                        options = listOf("auto", "stream-one (双向流)", "stream-down (分离上下行)"),
                        selectedIndex = when (xhttpMode) {
                            "stream-one" -> 1
                            "stream-down" -> 2
                            else -> 0
                        },
                        onSelectionChange = {
                            xhttpMode = when (it) {
                                1 -> "stream-one"
                                2 -> "stream-down"
                                else -> "auto"
                            }
                        }
                    )
                    OutlinedTextField(
                        value = xhttpPath,
                        onValueChange = { xhttpPath = it },
                        label = { Text("路径") },
                        placeholder = { Text("/xhttp") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                }
                EWPNode.TransportMode.H3GRPC -> {
                    OutlinedTextField(
                        value = grpcServiceName,
                        onValueChange = { grpcServiceName = it },
                        label = { Text("服务名 (ServiceName)") },
                        placeholder = { Text("ProxyService") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                    OutlinedTextField(
                        value = userAgent,
                        onValueChange = { userAgent = it },
                        label = { Text("User-Agent") },
                        placeholder = { Text("留空使用默认浏览器 UA") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                    OutlinedTextField(
                        value = contentType,
                        onValueChange = { contentType = it },
                        label = { Text("Content-Type") },
                        placeholder = { Text("仅 H3gRPC 有效，留空使用默认") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                }
            }

            Divider()
            SectionTitle("TLS 配置")

            SwitchRow("启用 TLS", enableTLS) { enableTLS = it }

            if (enableTLS) {
                SwitchRow("启用 ECH", enableECH) {
                    enableECH = it
                    if (it) minTLSVersion = "1.3"
                }

                if (enableECH) {
                    OutlinedTextField(
                        value = echDomain,
                        onValueChange = { echDomain = it },
                        label = { Text("ECH Config 域名") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                    OutlinedTextField(
                        value = dnsServer,
                        onValueChange = { dnsServer = it },
                        label = { Text("DoH 服务器") },
                        placeholder = { Text("dns.alidns.com/dns-query") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                }

                SwitchRow("后量子加密 (PQC)", enablePQC) { enablePQC = it }

                TextButton(onClick = { showAdvanced = !showAdvanced }) {
                    Text(if (showAdvanced) "隐藏高级 TLS 选项" else "显示高级 TLS 选项")
                }

                if (showAdvanced) {
                    OutlinedTextField(
                        value = sni,
                        onValueChange = { sni = it },
                        label = { Text("SNI") },
                        placeholder = { Text("留空则同 Host（TLS 握手域名）") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )

                    OutlinedTextField(
                        value = serverIP,
                        onValueChange = { serverIP = it },
                        label = { Text("优选 IP") },
                        placeholder = { Text("可选，绕过 DNS 直连 IP") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )

                    DropdownRow(
                        label = "最低 TLS 版本",
                        options = listOf("TLS 1.2", "TLS 1.3"),
                        selectedIndex = if (minTLSVersion == "1.3") 1 else 0,
                        onSelectionChange = {
                            if (!enableECH) minTLSVersion = if (it == 1) "1.3" else "1.2"
                        },
                        enabled = !enableECH
                    )
                }
            }
        }
    }
}

@Composable
private fun SectionTitle(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleMedium,
        color = MaterialTheme.colorScheme.primary
    )
}

@Composable
private fun SwitchRow(label: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(label, style = MaterialTheme.typography.bodyLarge)
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SegmentedButton(
    label: String,
    options: List<String>,
    selectedIndex: Int,
    onSelectionChange: (Int) -> Unit,
    modifier: Modifier = Modifier
) {
    Column(modifier = modifier) {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(4.dp))
        if (options.size <= 3) {
            Row(
                modifier = Modifier.fillMaxWidth(),
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
        } else {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                options.forEachIndexed { index, option ->
                    FilterChip(
                        selected = selectedIndex == index,
                        onClick = { onSelectionChange(index) },
                        label = { Text(option, style = MaterialTheme.typography.labelSmall) },
                        modifier = Modifier.weight(1f)
                    )
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DropdownRow(
    label: String,
    options: List<String>,
    selectedIndex: Int,
    onSelectionChange: (Int) -> Unit,
    enabled: Boolean = true
) {
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { if (enabled) expanded = !expanded }
    ) {
        OutlinedTextField(
            value = options[selectedIndex],
            onValueChange = {},
            readOnly = true,
            label = { Text(label) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier.fillMaxWidth().menuAnchor(),
            enabled = enabled
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            options.forEachIndexed { index, option ->
                DropdownMenuItem(
                    text = { Text(option) },
                    onClick = {
                        onSelectionChange(index)
                        expanded = false
                    }
                )
            }
        }
    }
}
