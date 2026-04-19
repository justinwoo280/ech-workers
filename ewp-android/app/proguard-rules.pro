# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.

# Keep ewpmobile classes
-keep class ewpmobile.** { *; }
-keep interface ewpmobile.** { *; }

# Keep serialization classes
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt

-keepclassmembers class kotlinx.serialization.json.** {
    *** Companion;
}
-keepclasseswithmembers class kotlinx.serialization.json.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# Keep data classes for serialization - refined to allow field name obfuscation
-keep @kotlinx.serialization.Serializable class * {
    <init>(...);
    *** Companion;
    public static *** Companion();
}

# Google Tink (EncryptedSharedPreferences) — compile-time annotations not in runtime classpath
-dontwarn com.google.errorprone.annotations.**
-dontwarn javax.annotation.**

# Keep Compose
-keep class androidx.compose.** { *; }
