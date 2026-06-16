# Keep JNI bridge class and native methods
-keep class com.example.securitysample.SecurityChecker {
    native <methods>;
    public void onThreatDetected(java.lang.String);
}

# Keep MainActivity
-keep class com.example.securitysample.MainActivity { *; }
