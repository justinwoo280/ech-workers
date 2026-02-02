package com.echworkers.android.data

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.util.Log
import com.echworkers.android.model.AppInfo
import com.echworkers.android.model.ProxyConfig
import com.echworkers.android.model.ProxyMode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class AppRepository(private val context: Context) {
    
    companion object {
        private const val TAG = "AppRepository"
        private const val PREFS_NAME = "proxy_config"
        private const val KEY_PROXY_CONFIG = "proxy_config_json"
    }
    
    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val json = Json { ignoreUnknownKeys = true }
    
    private val _installedApps = MutableStateFlow<List<AppInfo>>(emptyList())
    val installedApps: StateFlow<List<AppInfo>> = _installedApps.asStateFlow()
    
    private val _proxyConfig = MutableStateFlow(ProxyConfig())
    val proxyConfig: StateFlow<ProxyConfig> = _proxyConfig.asStateFlow()
    
    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()
    
    init {
        loadProxyConfig()
    }
    
    suspend fun loadInstalledApps() {
        withContext(Dispatchers.IO) {
            try {
                _isLoading.value = true
                
                val pm = context.packageManager
                val packages = pm.getInstalledApplications(PackageManager.GET_META_DATA)
                
                val apps = packages
                    .filter { it.packageName != context.packageName }
                    .map { appInfo ->
                        AppInfo(
                            packageName = appInfo.packageName,
                            appName = appInfo.loadLabel(pm).toString(),
                            icon = appInfo.loadIcon(pm),
                            isSystemApp = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                        )
                    }
                    .sorted()
                
                _installedApps.value = apps
                Log.i(TAG, "Loaded ${apps.size} apps")
                
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load apps", e)
            } finally {
                _isLoading.value = false
            }
        }
    }
    
    fun setProxyMode(mode: ProxyMode) {
        _proxyConfig.value = _proxyConfig.value.copy(mode = mode)
        saveProxyConfig()
        Log.i(TAG, "Proxy mode changed: $mode")
    }
    
    fun toggleAppSelection(packageName: String) {
        val current = _proxyConfig.value.selectedPackages
        val updated = if (packageName in current) {
            current - packageName
        } else {
            current + packageName
        }
        
        _proxyConfig.value = _proxyConfig.value.copy(selectedPackages = updated)
        saveProxyConfig()
        Log.d(TAG, "App selection toggled: $packageName, total=${updated.size}")
    }
    
    fun isAppSelected(packageName: String): Boolean {
        return packageName in _proxyConfig.value.selectedPackages
    }
    
    fun clearSelectedApps() {
        _proxyConfig.value = _proxyConfig.value.copy(selectedPackages = emptySet())
        saveProxyConfig()
        Log.i(TAG, "Selected apps cleared")
    }
    
    private fun saveProxyConfig() {
        try {
            val jsonString = json.encodeToString(_proxyConfig.value)
            prefs.edit().putString(KEY_PROXY_CONFIG, jsonString).apply()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to save proxy config", e)
        }
    }
    
    private fun loadProxyConfig() {
        try {
            val jsonString = prefs.getString(KEY_PROXY_CONFIG, null)
            if (jsonString != null) {
                _proxyConfig.value = json.decodeFromString(jsonString)
                Log.i(TAG, "Loaded proxy config: mode=${_proxyConfig.value.mode}, apps=${_proxyConfig.value.selectedPackages.size}")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load proxy config", e)
        }
    }
}
