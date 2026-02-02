package com.echworkers.android.ui.screen

import androidx.compose.foundation.Image
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
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import com.echworkers.android.model.AppInfo
import com.echworkers.android.model.ProxyMode
import com.echworkers.android.viewmodel.MainViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppSelectScreen(
    viewModel: MainViewModel,
    onNavigateBack: () -> Unit
) {
    val apps by viewModel.installedApps.collectAsState()
    val proxyConfig by viewModel.proxyConfig.collectAsState()
    val isLoading by viewModel.isLoadingApps.collectAsState()
    
    var showSystemApps by remember { mutableStateOf(false) }
    var searchQuery by remember { mutableStateOf("") }
    
    val filteredApps = apps.filter { app ->
        (showSystemApps || !app.isSystemApp) &&
        (searchQuery.isBlank() || 
         app.appName.contains(searchQuery, ignoreCase = true) ||
         app.packageName.contains(searchQuery, ignoreCase = true))
    }
    
    val selectedCount = proxyConfig.selectedPackages.size
    
    Scaffold(
        topBar = {
            Column {
                TopAppBar(
                    title = { Text("应用代理设置") },
                    navigationIcon = {
                        IconButton(onClick = onNavigateBack) {
                            Icon(Icons.Default.ArrowBack, "返回")
                        }
                    },
                    actions = {
                        IconButton(
                            onClick = { viewModel.loadApps() },
                            enabled = !isLoading
                        ) {
                            Icon(Icons.Default.Refresh, "刷新")
                        }
                    }
                )
                
                Column(
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    ProxyModeSelector(
                        selectedMode = proxyConfig.mode,
                        onModeChange = { viewModel.setProxyMode(it) }
                    )
                    
                    if (proxyConfig.mode != ProxyMode.GLOBAL) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = "已选择 $selectedCount 个应用",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.primary,
                                fontWeight = FontWeight.SemiBold
                            )
                            
                            if (selectedCount > 0) {
                                TextButton(onClick = { viewModel.clearSelectedApps() }) {
                                    Text("清空")
                                }
                            }
                        }
                    }
                    
                    OutlinedTextField(
                        value = searchQuery,
                        onValueChange = { searchQuery = it },
                        placeholder = { Text("搜索应用...") },
                        leadingIcon = {
                            Icon(Icons.Default.Search, "搜索")
                        },
                        trailingIcon = {
                            if (searchQuery.isNotEmpty()) {
                                IconButton(onClick = { searchQuery = "" }) {
                                    Icon(Icons.Default.Close, "清除")
                                }
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                    
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "显示系统应用",
                            style = MaterialTheme.typography.bodyMedium
                        )
                        Switch(
                            checked = showSystemApps,
                            onCheckedChange = { showSystemApps = it }
                        )
                    }
                }
                
                Divider()
            }
        }
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            if (isLoading) {
                CircularProgressIndicator(
                    modifier = Modifier.align(Alignment.Center)
                )
            } else if (filteredApps.isEmpty()) {
                EmptyAppsState(
                    modifier = Modifier.align(Alignment.Center),
                    hasSearch = searchQuery.isNotBlank()
                )
            } else {
                LazyColumn(
                    contentPadding = PaddingValues(vertical = 8.dp)
                ) {
                    items(
                        items = filteredApps,
                        key = { it.packageName }
                    ) { app ->
                        AppItem(
                            app = app,
                            isSelected = viewModel.isAppSelected(app.packageName),
                            enabled = proxyConfig.mode != ProxyMode.GLOBAL,
                            onToggle = {
                                if (proxyConfig.mode != ProxyMode.GLOBAL) {
                                    viewModel.toggleAppSelection(app.packageName)
                                }
                            }
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun ProxyModeSelector(
    selectedMode: ProxyMode,
    onModeChange: (ProxyMode) -> Unit
) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                text = "代理模式",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onPrimaryContainer
            )
            
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                ProxyMode.values().forEach { mode ->
                    FilterChip(
                        selected = selectedMode == mode,
                        onClick = { onModeChange(mode) },
                        label = { Text(mode.displayName()) },
                        modifier = Modifier.weight(1f)
                    )
                }
            }
            
            Text(
                text = selectedMode.description(),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onPrimaryContainer
            )
        }
    }
}

@Composable
private fun AppItem(
    app: AppInfo,
    isSelected: Boolean,
    enabled: Boolean,
    onToggle: () -> Unit
) {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(enabled = enabled, onClick = onToggle),
        color = if (isSelected && enabled) 
            MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.3f)
        else 
            MaterialTheme.colorScheme.surface
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            app.icon?.let { icon ->
                Image(
                    bitmap = icon.toBitmap(width = 48, height = 48).asImageBitmap(),
                    contentDescription = app.appName,
                    modifier = Modifier.size(48.dp)
                )
            } ?: run {
                Box(
                    modifier = Modifier.size(48.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        Icons.Default.Apps,
                        contentDescription = null,
                        modifier = Modifier.size(32.dp),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            
            Column(
                modifier = Modifier.weight(1f)
            ) {
                Text(
                    text = app.appName,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Medium
                )
                
                Text(
                    text = app.packageName,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                
                if (app.isSystemApp) {
                    Text(
                        text = "系统应用",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.tertiary
                    )
                }
            }
            
            if (enabled) {
                Checkbox(
                    checked = isSelected,
                    onCheckedChange = { onToggle() }
                )
            }
        }
    }
}

@Composable
private fun EmptyAppsState(
    modifier: Modifier = Modifier,
    hasSearch: Boolean
) {
    Column(
        modifier = modifier.padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Icon(
            if (hasSearch) Icons.Default.SearchOff else Icons.Default.Apps,
            contentDescription = null,
            modifier = Modifier.size(72.dp),
            tint = MaterialTheme.colorScheme.surfaceVariant
        )
        
        Spacer(Modifier.height(16.dp))
        
        Text(
            text = if (hasSearch) "未找到应用" else "暂无应用",
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        
        Text(
            text = if (hasSearch) "尝试修改搜索条件" else "加载应用列表中...",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
