package com.echworkers.android.data

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.util.Log
import com.echworkers.android.model.EWPNode
import com.echworkers.android.model.ProxyConfig
import com.echworkers.android.model.VpnState
import com.echworkers.android.model.VpnStats
import com.echworkers.android.service.*
import ewpmobile.Ewpmobile
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class VpnRepository(private val context: Context) {
    
    companion object {
        private const val TAG = "VpnRepository"
    }
    
    private val json = Json { ignoreUnknownKeys = true }
    
    private val _state = MutableStateFlow<VpnState>(VpnState.Disconnected)
    val state: StateFlow<VpnState> = _state.asStateFlow()
    
    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                VPN_STATE_ACTION -> {
                    val stateName = intent.getStringExtra(EXTRA_STATE) ?: return
                    handleStateChange(stateName)
                }
                VPN_STATS_ACTION -> {
                    val statsJson = intent.getStringExtra(EXTRA_STATS) ?: return
                    handleStats(statsJson)
                }
                VPN_ERROR_ACTION -> {
                    val error = intent.getStringExtra(EXTRA_ERROR) ?: "Unknown error"
                    handleError(error)
                }
            }
        }
    }
    
    init {
        registerReceiver()
        
        if (Ewpmobile.isVPNRunning()) {
            _state.value = VpnState.Connected(VpnStats())
        }
    }
    
    fun connect(node: EWPNode, proxyConfig: ProxyConfig) {
        try {
            val intent = Intent(context, EWPVpnService::class.java).apply {
                action = EWPVpnService.ACTION_START
                putExtra(EWPVpnService.EXTRA_NODE_JSON, json.encodeToString(node))
                putExtra(EWPVpnService.EXTRA_PROXY_CONFIG_JSON, json.encodeToString(proxyConfig))
            }
            context.startService(intent)
            
            Log.i(TAG, "Connect request sent: ${node.name}, mode=${proxyConfig.mode}")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to connect", e)
            _state.value = VpnState.Error(e.message ?: "Unknown error")
        }
    }
    
    fun disconnect() {
        try {
            val intent = Intent(context, EWPVpnService::class.java).apply {
                action = EWPVpnService.ACTION_STOP
            }
            context.startService(intent)
            
            Log.i(TAG, "Disconnect request sent")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to disconnect", e)
        }
    }
    
    fun isRunning(): Boolean {
        return Ewpmobile.isVPNRunning()
    }
    
    private fun handleStateChange(stateName: String) {
        _state.value = when (VpnServiceState.valueOf(stateName)) {
            VpnServiceState.DISCONNECTED -> VpnState.Disconnected
            VpnServiceState.CONNECTING -> VpnState.Connecting
            VpnServiceState.CONNECTED -> {
                val statsJson = Ewpmobile.getVPNStats()
                val stats = VpnStats.fromJson(statsJson)
                VpnState.Connected(stats)
            }
            VpnServiceState.DISCONNECTING -> VpnState.Disconnecting
        }
        Log.d(TAG, "State changed: $stateName")
    }
    
    private fun handleStats(statsJson: String) {
        val stats = VpnStats.fromJson(statsJson)
        _state.value = VpnState.Connected(stats)
    }
    
    private fun handleError(error: String) {
        _state.value = VpnState.Error(error)
        Log.e(TAG, "VPN error: $error")
    }
    
    private fun registerReceiver() {
        val filter = IntentFilter().apply {
            addAction(VPN_STATE_ACTION)
            addAction(VPN_STATS_ACTION)
            addAction(VPN_ERROR_ACTION)
        }
        context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
    }
    
    fun unregister() {
        try {
            context.unregisterReceiver(receiver)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to unregister receiver", e)
        }
    }
}
