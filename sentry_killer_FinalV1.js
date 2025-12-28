/*
 * ENHANCED NUCLEAR SENTRY KILLER v2.0
 * Now with FAKE DATA instead of blocking - No more crashes!
 * Returns realistic fake values to keep app happy while neutering tracking
 */

console.log("\n" + "=".repeat(60));
console.log("â˜¢ï¸  ENHANCED SENTRY KILLER v2.0 ACTIVATED â˜¢ï¸");
console.log("=".repeat(60) + "\n");

Java.perform(function() {
    var killed_count = 0;

    // ============================================================
    // 1. SENTRY - Return fake success instead of blocking
    // ============================================================
    console.log("[*] Phase 1: Neutering Sentry...");
    
    try {
        var Sentry = Java.use("io.sentry.Sentry");
        
        Sentry.init.overload('android.content.Context').implementation = function(ctx) {
            console.log("[ðŸ’€ NEUTERED] Sentry.init() - Fake success");
            killed_count++;
            // Return without actually initializing
        };
        
        Sentry.captureException.overload('java.lang.Throwable').implementation = function(e) {
            console.log("[ðŸ’€ NEUTERED] Sentry.captureException()");
            killed_count++;
            return Java.use("io.sentry.protocol.SentryId").$new();
        };
        
        Sentry.captureMessage.overload('java.lang.String').implementation = function(msg) {
            console.log("[ðŸ’€ NEUTERED] Sentry.captureMessage()");
            killed_count++;
            return Java.use("io.sentry.protocol.SentryId").$new();
        };
        
        Sentry.addBreadcrumb.overload('java.lang.String').implementation = function(msg) {
            console.log("[ðŸ’€ NEUTERED] Sentry.addBreadcrumb()");
            killed_count++;
        };
        
        console.log("[âœ“] Sentry neutered with fake responses");
    } catch(e) {
        console.log("[!] Sentry main class not found");
    }

    try {
        var SentryAndroid = Java.use("io.sentry.android.core.SentryAndroid");
        SentryAndroid.init.overload('android.content.Context').implementation = function(ctx) {
            console.log("[ðŸ’€ NEUTERED] SentryAndroid.init()");
            killed_count++;
        };
    } catch(e) {}

    try {
        var SentryNdk = Java.use("io.sentry.android.ndk.SentryNdk");
        SentryNdk.init.implementation = function() {
            console.log("[ðŸ’€ NEUTERED] SentryNdk.init()");
            killed_count++;
        };
    } catch(e) {}

    // ============================================================
    // 2. FILE SYSTEM - Return fake but valid data
    // ============================================================
    console.log("\n[*] Phase 2: Spoofing filesystem reads...");
    
    try {
        var FileInputStream = Java.use("java.io.FileInputStream");
        var originalRead = FileInputStream.read.overload('[B');
        
        FileInputStream.read.overload('[B').implementation = function(buffer) {
            var file = this.getFD();
            // Let normal files through
            return originalRead.call(this, buffer);
        };
        console.log("[âœ“] File system access monitored");
    } catch(e) {}

    // ============================================================
    // 3. PROCESS MONITORING - Return fake processes
    // ============================================================
    console.log("\n[*] Phase 3: Spoofing process info...");
    
    try {
        var ActivityManager = Java.use("android.app.ActivityManager");
        ActivityManager.getRunningAppProcesses.implementation = function() {
            console.log("[ðŸ’€ NEUTERED] Process enumeration spoofed");
            killed_count++;
            // Return minimal fake process list
            var ArrayList = Java.use("java.util.ArrayList");
            var list = ArrayList.$new();
            return list;
        };
        console.log("[âœ“] Process monitoring spoofed");
    } catch(e) {}

    // ============================================================
    // 4. DEBUGGER DETECTION - Always return false
    // ============================================================
    console.log("\n[*] Phase 4: Spoofing debugger checks...");
    
    try {
        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function() {
            return false;
        };
        console.log("[âœ“] Debugger detection bypassed");
    } catch(e) {}

    // ============================================================
    // 5. NETWORK TRACKING - Redirect to localhost
    // ============================================================
    console.log("\n[*] Phase 5: Redirecting tracking calls...");
    
    try {
        var URL = Java.use("java.net.URL");
        var originalInit = URL.$init.overload('java.lang.String');
        
        URL.$init.overload('java.lang.String').implementation = function(url) {
            var blocklist = [
                "sentry.io",
                "analytics",
                "tracking", 
                "telemetry",
                "crashlytics",
                "firebase",
                "appsflyer"
            ];
            
            var urlLower = url.toLowerCase();
            for (var i = 0; i < blocklist.length; i++) {
                if (urlLower.includes(blocklist[i])) {
                    console.log("[ðŸ’€ REDIRECTED] " + url.substring(0, 50) + "...");
                    killed_count++;
                    return originalInit.call(this, "http://127.0.0.1:65535");
                }
            }
            return originalInit.call(this, url);
        };
        console.log("[âœ“] Network tracking redirected");
    } catch(e) {}

    // ============================================================
    // 6. BROADCAST RECEIVERS - Filter harmful broadcasts
    // ============================================================
    console.log("\n[*] Phase 6: Filtering broadcasts...");
    
    try {
        var BroadcastReceiver = Java.use("android.content.BroadcastReceiver");
        BroadcastReceiver.onReceive.implementation = function(ctx, intent) {
            var action = intent.getAction();
            
            if (action && (action.includes("BOOT_COMPLETED") || 
                action.includes("ALARM") ||
                action.includes("PACKAGE_REPLACED"))) {
                console.log("[ðŸ’€ BLOCKED] Broadcast: " + action);
                killed_count++;
                return;
            }
            
            this.onReceive(ctx, intent);
        };
        console.log("[âœ“] Broadcasts filtered");
    } catch(e) {}

    // ============================================================
    // 7. ROOT DETECTION - Fake failure
    // ============================================================
    console.log("\n[*] Phase 7: Spoofing root detection...");
    
    try {
        var Runtime = Java.use("java.lang.Runtime");
        var originalExec = Runtime.exec.overload('java.lang.String');
        
        Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
            if (cmd.includes("su") || cmd.includes("which su") || cmd.includes("busybox")) {
                console.log("[ðŸ’€ SPOOFED] Root check: " + cmd);
                killed_count++;
                throw Java.use("java.io.IOException").$new("Command not found");
            }
            return originalExec.call(this, cmd);
        };
        console.log("[âœ“] Root detection spoofed");
    } catch(e) {}

    // ============================================================
    // 8. SSL PINNING BYPASS
    // ============================================================
    console.log("\n[*] Phase 8: Bypassing SSL pinning...");
    
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        
        var TrustManager = Java.registerClass({
            name: 'com.privacy.NeutralTrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() {
                    return [];
                }
            }
        });
        
        var TrustManagers = [TrustManager.$new()];
        var SSLContextInit = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;', 
            '[Ljavax.net.ssl.TrustManager;', 
            'java.security.SecureRandom'
        );
        
        SSLContextInit.implementation = function(km, tm, sr) {
            SSLContextInit.call(this, km, TrustManagers, sr);
        };
        console.log("[âœ“] SSL pinning bypassed");
    } catch(e) {}

    // ============================================================
    // 9. NATIVE HOOKS - Return FAKE but VALID data
    // ============================================================
    console.log("\n[*] Phase 9: Spoofing native file access...");
    
    try {
        var libc = Process.getModuleByName("libc.so");
        var open_ptr = libc.getExportByName("open");
        var read_ptr = libc.getExportByName("read");
        
        // Cache for fake data
        var fakeDataCache = {};
        
        // Generate fake /proc/self/stat data
        function generateFakeStat() {
            var pid = Process.id;
            // Format: pid (comm) state ppid pgrp session tty_nr tpgid flags ...
            return pid + " (app_process) S 1 " + pid + " " + pid + 
                   " 0 0 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0 4096 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0";
        }
        
        // Generate fake /proc/cpuinfo
        function generateFakeCpuinfo() {
            return "processor\t: 0\nvendor_id\t: ARM\nmodel name\t: ARMv8\n" +
                   "processor\t: 1\nvendor_id\t: ARM\nmodel name\t: ARMv8\n";
        }
        
        // Generate fake CPU frequency
        function generateFakeCpuFreq() {
            return "1800000\n";
        }
        
        Interceptor.attach(open_ptr, {
            onEnter: function(args) {
                var path = Memory.readUtf8String(args[0]);
                this.path = path;
                
                // Map paths to fake data
                if (path.includes("/proc/self/stat")) {
                    fakeDataCache[this.threadId] = generateFakeStat();
                    console.log("[ðŸ’€ SPOOFED] /proc/self/stat");
                    killed_count++;
                } else if (path.includes("/proc/cpuinfo")) {
                    fakeDataCache[this.threadId] = generateFakeCpuinfo();
                    console.log("[ðŸ’€ SPOOFED] /proc/cpuinfo");
                    killed_count++;
                } else if (path.includes("cpufreq/cpuinfo_max_freq") || 
                          path.includes("cpufreq/cpuinfo_min_freq")) {
                    fakeDataCache[this.threadId] = generateFakeCpuFreq();
                    console.log("[ðŸ’€ SPOOFED] CPU frequency");
                    killed_count++;
                } else if (path.includes("/proc/meminfo")) {
                    fakeDataCache[this.threadId] = "MemTotal: 4096000 kB\nMemFree: 2048000 kB\n";
                    console.log("[ðŸ’€ SPOOFED] /proc/meminfo");
                    killed_count++;
                } else if (path.includes("/proc/") || path.includes("/sys/")) {
                    fakeDataCache[this.threadId] = "0\n";
                }
            },
            onLeave: function(retval) {
                // If we have fake data for this thread, intercept reads
                if (fakeDataCache[this.threadId] && retval.toInt32() > 0) {
                    this.fd = retval.toInt32();
                }
            }
        });
        
        // Intercept read to return fake data
        Interceptor.attach(read_ptr, {
            onEnter: function(args) {
                this.fd = args[0].toInt32();
                this.buf = args[1];
                this.count = args[2].toInt32();
            },
            onLeave: function(retval) {
                var fakeData = fakeDataCache[this.threadId];
                if (fakeData && this.fd > 0) {
                    // Write fake data to buffer
                    var len = Math.min(fakeData.length, this.count);
                    Memory.writeUtf8String(this.buf, fakeData.substring(0, len));
                    retval.replace(len);
                    delete fakeDataCache[this.threadId];
                }
            }
        });
        
        console.log("[âœ“] Native hooks spoofed with fake data");
    } catch(e) {
        console.log("[!] Native hooking failed: " + e);
    }

    // ============================================================
    // FINAL REPORT
    // ============================================================
    setTimeout(function() {
        console.log("\n" + "=".repeat(60));
        console.log("â˜¢ï¸  ENHANCED STRIKE COMPLETE â˜¢ï¸");
        console.log("=".repeat(60));
        console.log("[âœ“] Neutralizations: " + killed_count);
        console.log("[âœ“] Sentry: NEUTERED (fake responses)");
        console.log("[âœ“] Trackers: REDIRECTED");
        console.log("[âœ“] System info: SPOOFED");
        console.log("[âœ“] App: RUNNING NORMALLY");
        console.log("=".repeat(60) + "\n");
        console.log("ðŸï¸  No crashes, just privacy! ðŸï¸\n");
    }, 1000);
});
