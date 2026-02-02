package com.echworkers.android.model

import android.graphics.drawable.Drawable

data class AppInfo(
    val packageName: String,
    val appName: String,
    val icon: Drawable?,
    val isSystemApp: Boolean
) : Comparable<AppInfo> {
    override fun compareTo(other: AppInfo): Int {
        if (isSystemApp != other.isSystemApp) {
            return if (isSystemApp) 1 else -1
        }
        return appName.compareTo(other.appName, ignoreCase = true)
    }
}
