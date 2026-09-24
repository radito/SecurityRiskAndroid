# Keep JNI bridge class and native methods
-keep class com.example.securitysample.SecurityChecker {
    native <methods>;
    public void onThreatDetected(java.lang.String);
}

# Keep MainActivity
-keep class com.example.securitysample.MainActivity { *; }

# Instantiated by the platform app-zygote process from the manifest.
-keep class com.example.securitysample.SecurityAppZygote { *; }
