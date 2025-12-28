/**
 * COMBINED SCRIPT: Sentry Killer (patches) + Safer Discovery (recorder)
 * Usage: frida -U -f com.your.package.name -l sentry_AllInOne.js --no-pause
 *
 * What changed:
 * - Discovery hooks now store original overload implementations and call them (prevents recursion).
 * - Discovery aggregates counters and sample stack traces per method.
 * - At report time, the script prints suggested patch snippets for the top suspicious methods.
 * - Sentry-Killer (destructive patches) preserved as-is (you wanted aggressive neutralization).
 *
 * Goal: observe first, then patch precisely. Privacy-only intention assumed.
 */

console.log("\n" + "=".repeat(60));
console.log("â˜¢ï¸  SENTRY KILLER v3.0 + SAFER DISCOVERY MODE â˜¢ï¸");
console.log("=".repeat(60) + "\n");

Java.perform(function () {
    // globals
    var killed_count = 0;
    var blocked_urls = [];
    var validationPoints = [];
    var sentryMethods = [];

    // discovery stats: { methodFullName: { count: n, samples: [ {args, ret, stack} ] } }
    var discoveryStats = {};

    const colors = {
        reset: '\x1b[0m',
        red: '\x1b[31m',
        green: '\x1b[32m',
        yellow: '\x1b[33m',
        blue: '\x1b[34m',
        magenta: '\x1b[35m',
        cyan: '\x1b[36m'
    };

    function safeJson(x) {
        try { return JSON.stringify(x); } catch (e) { return "[unserializable]"; }
    }

    function recordDiscovery(methodFullName, args, ret) {
        try {
            var stack = "[no stack]";
            try {
                stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            } catch (e) {}
            if (!discoveryStats[methodFullName]) discoveryStats[methodFullName] = { count: 0, samples: [] };
            discoveryStats[methodFullName].count++;
            if (discoveryStats[methodFullName].samples.length < 5) { // keep up to 5 samples
                discoveryStats[methodFullName].samples.push({ args: args, ret: ret, stack: stack, t: Date.now() });
            }
        } catch (e) {
            // don't crash discovery
        }
    }

    // -----------------------------
    // PART A: SENTRY KILLER (destructive patches)
    // -----------------------------
    function patchSentryFunctions() {
        console.log(colors.red + "\n[PATCH MODE] Applying Sentry Killer patches..." + colors.reset);

        // 1. Sentry core
        try {
            var Sentry = Java.use("io.sentry.Sentry");
            try {
                Sentry.init.overload('android.content.Context').implementation = function (ctx) {
                    console.log("[ðŸ’€ NEUTERED] Sentry.init()");
                    killed_count++;
                    return;
                };
            } catch (e) {}
            try {
                Sentry.captureException.overload('java.lang.Throwable').implementation = function (e) {
                    console.log("[ðŸ’€ NEUTERED] Sentry.captureException()");
                    killed_count++;
                    try { return Java.use("io.sentry.protocol.SentryId").$new(); } catch (ex) { return null; }
                };
            } catch (e) {}
            try {
                Sentry.captureMessage.overload('java.lang.String').implementation = function (msg) {
                    console.log("[ðŸ’€ NEUTERED] Sentry.captureMessage()");
                    killed_count++;
                    try { return Java.use("io.sentry.protocol.SentryId").$new(); } catch (ex) { return null; }
                };
            } catch (e) {}
            console.log("[âœ“] Sentry SDK neutered");
        } catch (e) {
            console.log("[!] Sentry not found (might be obfuscated)");
        }

        // Sentry Android core/ndk
        try {
            var SentryAndroid = Java.use("io.sentry.android.core.SentryAndroid");
            try { SentryAndroid.init.overload('android.content.Context').implementation = function(ctx) { console.log("[ðŸ’€ NEUTERED] SentryAndroid.init()"); killed_count++; }; } catch(e) {}
        } catch(e){}
        try {
            var SentryNdk = Java.use("io.sentry.android.ndk.SentryNdk");
            try { SentryNdk.init.implementation = function() { console.log("[ðŸ’€ NEUTERED] SentryNdk.init()"); killed_count++; }; } catch(e) {}
        } catch(e){}

        // 2. Block java.net.URL constructor based on blocklist
        try {
            var URL = Java.use("java.net.URL");
            var originalInit = URL.$init.overload('java.lang.String');
            URL.$init.overload('java.lang.String').implementation = function (url) {
                try {
                    var blocklist = ["sentry.io","firebaselogging.googleapis.com","google-analytics.com","analytics","tracking","telemetry","crashlytics","appsflyer"];
                    var urlLower = (url || "").toLowerCase();
                    for (var i = 0; i < blocklist.length; i++) {
                        if (urlLower.includes(blocklist[i])) {
                            try { console.log("[ðŸ’€ BLOCKED] " + (url && url.substring ? url.substring(0,60) : url) + "..."); } catch(e) { console.log("[ðŸ’€ BLOCKED] url"); }
                            killed_count++;
                            blocked_urls.push(url && url.substring ? url.substring(0,60) : url);
                            return originalInit.call(this, "http://127.0.0.1:65535/blocked");
                        }
                    }
                } catch (e) {}
                return originalInit.call(this, url);
            };
            console.log("[âœ“] java.net.URL tracking blocked");
        } catch (e) {
            console.log("[!] Could not hook java.net.URL: " + e);
        }

        // 3. OkHttp Request.Builder.url(String)
        try {
            var RequestBuilder = Java.use("okhttp3.Request$Builder");
            var originalUrl = RequestBuilder.url.overload('java.lang.String');
            RequestBuilder.url.overload('java.lang.String').implementation = function (url) {
                try {
                    var blocklist = ["sentry.io","firebaselogging.googleapis.com","google-analytics.com"];
                    var urlLower = (url || "").toLowerCase();
                    for (var i = 0; i < blocklist.length; i++) {
                        if (urlLower.includes(blocklist[i])) {
                            try { console.log("[ðŸ’€ BLOCKED OkHttp] " + (url && url.substring ? url.substring(0,60) : url) + "..."); } catch(e) { console.log("[ðŸ’€ BLOCKED OkHttp] url"); }
                            killed_count++;
                            return originalUrl.call(this, "http://127.0.0.1:65535/blocked");
                        }
                    }
                } catch (e) {}
                return originalUrl.call(this, url);
            };
            console.log("[âœ“] OkHttp tracking blocked");
        } catch (e) {
            console.log("[!] OkHttp not found (app might not use it)");
        }

        // 4. WebView injection - inject JS stub & fetch/XHR blocking
        try {
            var WebView = Java.use("android.webkit.WebView");
            var originalLoadUrl = WebView.loadUrl.overload('java.lang.String');
            var blockingScript = `
                javascript:(function(){
                    if (typeof window !== 'undefined') {
                        window.Sentry = { init:function(){}, captureException:function(){}, captureMessage:function(){}, captureEvent:function(){}, addBreadcrumb:function(){} };
                    }
                    if (window.fetch) {
                        const origFetch = window.fetch;
                        window.fetch = function(input, init){
                            const url = (typeof input === 'string') ? input : (input && input.url) || '';
                            if (url.includes('sentry.io') || url.includes('firebaselogging.googleapis.com') || url.includes('google-analytics.com')) {
                                return Promise.resolve(new Response(JSON.stringify({status:'ok'}), {status:200, headers:{'Content-Type':'application/json'}}));
                            }
                            return origFetch.apply(this, arguments);
                        };
                    }
                    if (window.XMLHttpRequest) {
                        const origOpen = XMLHttpRequest.prototype.open;
                        XMLHttpRequest.prototype.open = function(method, url){
                            this._url = url; return origOpen.apply(this, arguments);
                        };
                        const origSend = XMLHttpRequest.prototype.send;
                        XMLHttpRequest.prototype.send = function(body){
                            if (this._url && (this._url.includes('sentry.io') || this._url.includes('firebaselogging.googleapis.com') || this._url.includes('google-analytics.com'))) {
                                this.readyState = 4; this.status = 200; this.response = JSON.stringify({status:'ok'}); if (this.onreadystatechange) this.onreadystatechange(); if (this.onload) this.onload(); return;
                            }
                            return origSend.apply(this, arguments);
                        };
                    }
                })();
            `;
            WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
                try { console.log("[*] WebView loading: " + (url && url.substring ? url.substring(0,60) : url)); } catch(e) {}
                originalLoadUrl.call(this, url);
                try { this.loadUrl(blockingScript); console.log("[âœ“] Injected tracker blocker into WebView"); } catch(e) { console.log("[!] Failed to inject script: " + e); }
            };
            console.log("[âœ“] WebView hooking enabled");
        } catch (e) { console.log("[!] Could not hook WebView: " + e); }

        // 5. WebViewClient.shouldInterceptRequest -> return fake JSON for blocked hosts
        try {
            var WebViewClient = Java.use("android.webkit.WebViewClient");
            WebViewClient.shouldInterceptRequest.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest').implementation = function (view, request) {
                try {
                    var url = request.getUrl().toString();
                    var blocklist = ["sentry.io","firebaselogging.googleapis.com","google-analytics.com","doubleclick.net","googlesyndication.com"];
                    for (var i = 0; i < blocklist.length; i++) {
                        if (url.toLowerCase().includes(blocklist[i])) {
                            killed_count++;
                            try {
                                var WebResourceResponse = Java.use("android.webkit.WebResourceResponse");
                                var ByteArrayInputStream = Java.use("java.io.ByteArrayInputStream");
                                var HashMap = Java.use("java.util.HashMap");
                                var fakeData = '{"status":"ok"}';
                                var bytes = Java.array('byte', fakeData.split('').map(function(c){ return c.charCodeAt(0); }));
                                var stream = ByteArrayInputStream.$new(bytes);
                                var headers = HashMap.$new();
                                headers.put("Content-Type", "application/json");
                                try { return WebResourceResponse.$new("application/json","utf-8",200,"OK",headers,stream); } catch(err) {
                                    try { return WebResourceResponse.$new("application/json","utf-8",stream); } catch(err2) { return null; }
                                }
                            } catch (e) { return null; }
                        }
                    }
                } catch (e) {}
                return this.shouldInterceptRequest(view, request);
            };
            console.log("[âœ“] WebViewClient intercept enabled");
        } catch (e) { console.log("[!] Could not hook WebViewClient: " + e); }

        // 6. Disable some boot receivers (best-effort)
        try {
            var BroadcastReceiver = Java.use("android.content.BroadcastReceiver");
            BroadcastReceiver.onReceive.implementation = function (ctx, intent) {
                try {
                    var action = intent.getAction();
                    if (action && (action.includes("BOOT_COMPLETED") || action.includes("QUICKBOOT_POWERON") || action.includes("ALARM"))) {
                        console.log("[ðŸ’€ BLOCKED] Boot/Alarm broadcast: " + action);
                        killed_count++;
                        return;
                    }
                } catch (e) {}
                this.onReceive(ctx, intent);
            };
            console.log("[âœ“] Boot receivers disabled");
        } catch (e) {}

        // 7. SSL pinning bypass (register permissive TrustManager)
        try {
            var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            var SSLContext = Java.use("javax.net.ssl.SSLContext");
            var TrustManager = Java.registerClass({
                name: 'com.privacy.UniversalTrustManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function (chain, authType) {},
                    checkServerTrusted: function (chain, authType) {},
                    getAcceptedIssuers: function () { return []; }
                }
            });
            var TrustManagers = [TrustManager.$new()];
            var SSLContextInit = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;','[Ljavax.net.ssl.TrustManager;','java.security.SecureRandom');
            SSLContextInit.implementation = function (km, tm, sr) {
                SSLContextInit.call(this, km, TrustManagers, sr);
            };
            console.log("[âœ“] SSL pinning bypassed");
        } catch (e) {}

        // 8. Minimal root detection bypass (Runtime.exec)
        try {
            var Runtime = Java.use("java.lang.Runtime");
            var originalExec = Runtime.exec.overload('java.lang.String');
            Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
                try {
                    if (cmd && (cmd.indexOf("su") !== -1 || cmd.indexOf("which su") !== -1)) {
                        console.log("[ðŸ’€ BLOCKED] Root check: " + cmd);
                        killed_count++;
                        throw Java.use("java.io.IOException").$new("Command not found");
                    }
                } catch (e) {}
                return originalExec.call(this, cmd);
            };
            console.log("[âœ“] Root detection bypassed");
        } catch (e) {}

        // 9. Debugger detection bypass
        try {
            var Debug = Java.use("android.os.Debug");
            Debug.isDebuggerConnected.implementation = function () { return false; };
            console.log("[âœ“] Debugger detection bypassed");
        } catch (e) {}

        // quick summary
        setTimeout(function () {
            console.log("\n" + "=".repeat(60));
            console.log("â˜¢ï¸  SENTRY KILLER v3.0 COMPLETE â˜¢ï¸");
            console.log("=".repeat(60));
            console.log("[âœ“] Total interventions: " + killed_count);
            console.log("=".repeat(60));
            if (blocked_urls.length > 0) {
                console.log("\n[*] Blocked URLs (sample):");
                for (var i = 0; i < Math.min(10, blocked_urls.length); i++) console.log("    - " + blocked_urls[i]);
            }
            console.log("\nðŸï¸  App should work normally now! ðŸï¸\n");
        }, 2000);
    }

    // -----------------------------
    // PART B: SAFER DISCOVERY / RECORDER
    // non-destructive observation that stores original impls
    // -----------------------------
    function hookSentryClasses() {
        console.log(colors.cyan + "\n[DISCOVERY] Hooking Sentry classes (safe mode)..." + colors.reset);

        Java.enumerateLoadedClasses({
            onMatch: function (className) {
                try {
                    if (!className) return;
                    var lcn = className.toLowerCase();
                    if (lcn.indexOf("sentry") !== -1 || lcn.indexOf("io.sentry") !== -1) {
                        try {
                            var clazz = Java.use(className);
                            var methods = clazz.class.getDeclaredMethods();
                            methods.forEach(function (method) {
                                var methodName = method.getName();
                                if (methodName.indexOf("toString") !== -1 || methodName.indexOf("hashCode") !== -1 || methodName.indexOf("equals") !== -1) return;
                                try {
                                    var overloadWrapper = clazz[methodName];
                                    if (!overloadWrapper || !overloadWrapper.overloads) return;
                                    overloadWrapper.overloads.forEach(function (overload) {
                                        try {
                                            // save original impl reference BEFORE override
                                            var originalImpl = overload.implementation;
                                            overload.implementation = function () {
                                                var args = Array.prototype.slice.call(arguments);
                                                var ret;
                                                try {
                                                    // call the saved original impl (safer)
                                                    if (typeof originalImpl === 'function') {
                                                        ret = originalImpl.apply(this, arguments);
                                                    } else {
                                                        // fallback if originalImpl is not a function:
                                                        ret = overload.apply(this, arguments);
                                                    }
                                                } catch (e) {
                                                    try { ret = overload.apply(this, arguments); } catch (e2) { ret = undefined; }
                                                }

                                                var fullName = className + "." + methodName;
                                                sentryMethods.push({ method: fullName, args: args, return: ret });
                                                recordDiscovery(fullName, args, ret);

                                                console.log(colors.blue + "\n[SENTRY CALL] " + colors.reset + fullName);
                                                console.log("  Args: " + safeJson(args));
                                                console.log("  Return: " + ret);
                                                return ret;
                                            };
                                        } catch (e) {}
                                    });
                                } catch (e) {}
                            });
                            console.log(colors.green + "[+] Hooked: " + className + colors.reset);
                        } catch (e) {}
                    }
                } catch (e) {}
            },
            onComplete: function () {
                console.log(colors.cyan + "[DISCOVERY] Sentry-class enumeration complete\n" + colors.reset);
            }
        });
    }

    function hookValidationMethods() {
        console.log(colors.cyan + "\n[DISCOVERY] Hooking validation methods (safe mode)..." + colors.reset);
        var suspiciousPatterns = ["verify","validate","check","isvalid","ensure","security","fraud","anomaly","health","monitor","integrity","analytics","tracking","detect"];
        Java.enumerateLoadedClasses({
            onMatch: function (className) {
                try {
                    if (!className) return;
                    if (className.startsWith("android.") || className.startsWith("java.") || className.startsWith("javax.") || className.startsWith("kotlin.")) return;
                    try {
                        var clazz = Java.use(className);
                        var methods = clazz.class.getDeclaredMethods();
                        methods.forEach(function (method) {
                            try {
                                var methodName = method.getName().toLowerCase();
                                var suspicious = suspiciousPatterns.some(function (p) { return methodName.indexOf(p) !== -1; });
                                if (!suspicious) return;
                                var fullName = className + "." + method.getName();
                                try {
                                    var overloadWrapper = clazz[method.getName()];
                                    if (!overloadWrapper || !overloadWrapper.overloads) return;
                                    overloadWrapper.overloads.forEach(function (overload) {
                                        try {
                                            var originalImpl = overload.implementation;
                                            overload.implementation = function () {
                                                var args = Array.prototype.slice.call(arguments);
                                                var ret;
                                                try {
                                                    if (typeof originalImpl === 'function') ret = originalImpl.apply(this, arguments);
                                                    else ret = overload.apply(this, arguments);
                                                } catch (e) {
                                                    try { ret = overload.apply(this, arguments); } catch (e2) { ret = undefined; }
                                                }

                                                console.log(colors.yellow + "\n[VALIDATION CHECK] " + colors.reset + fullName);
                                                console.log("  Args: " + safeJson(args));
                                                console.log("  Return: " + ret);
                                                try { console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())); } catch (e) {}

                                                validationPoints.push({ method: fullName, args: args, return: ret, timestamp: Date.now() });
                                                recordDiscovery(fullName, args, ret);
                                                return ret;
                                            };
                                        } catch (e) {}
                                    });
                                    console.log(colors.green + "[+] Hooked validation: " + fullName + colors.reset);
                                } catch (e) {}
                            } catch (e) {}
                        });
                    } catch (e) {}
                } catch (e) {}
            },
            onComplete: function () {
                console.log(colors.cyan + "[DISCOVERY] Validation-method enumeration complete\n" + colors.reset);
            }
        });
    }

    function hookNetworkCalls() {
        console.log(colors.cyan + "\n[DISCOVERY] Hooking network calls (OkHttp + HttpURLConnection)..." + colors.reset);
        // OkHttp RealCall.execute
        try {
            var Buffer = Java.use("okio.Buffer");
            var RealCall = Java.use("okhttp3.internal.connection.RealCall");
            // save original impl if any
            try {
                var originalExec = RealCall.execute.implementation;
            } catch (e) { var originalExec = null; }

            RealCall.execute.implementation = function () {
                try {
                    var request = this.request();
                    var url = request.url().toString();
                    var method = request.method();

                    if (url && (url.indexOf("sentry") !== -1 || url.indexOf("analytics") !== -1 || url.indexOf("track") !== -1 || url.indexOf("metric") !== -1)) {
                        console.log(colors.magenta + "\n[NETWORK TRACKER] " + colors.reset);
                        console.log("  Method: " + method);
                        console.log("  URL: " + url);
                        try {
                            var body = request.body();
                            if (body) {
                                var buf = Buffer.$new();
                                body.writeTo(buf);
                                var bodyStr = buf.readUtf8();
                                console.log("  Body: " + bodyStr);
                            }
                        } catch (e) {}
                        try { console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())); } catch (e) {}
                    }
                } catch (e) {}
                // call original implementation safely
                try {
                    if (typeof originalExec === 'function') return originalExec.apply(this, arguments);
                    return this.execute();
                } catch (e) {
                    try { return this.execute(); } catch (e2) { return null; }
                }
            };
            console.log(colors.green + "[+] Hooked OkHttp network calls" + colors.reset);
        } catch (e) { console.log(colors.red + "[-] OkHttp not found or already hooked" + colors.reset); }

        // HttpURLConnection.connect
        try {
            var HttpURLConnection = Java.use("java.net.HttpURLConnection");
            try {
                var originalConnect = HttpURLConnection.connect.implementation;
            } catch (e) { var originalConnect = null; }
            HttpURLConnection.connect.implementation = function () {
                try {
                    var url = this.getURL().toString();
                    if (url && (url.indexOf("sentry") !== -1 || url.indexOf("analytics") !== -1 || url.indexOf("track") !== -1)) {
                        console.log(colors.magenta + "\n[NETWORK TRACKER - HttpURLConnection]" + colors.reset);
                        console.log("  URL: " + url);
                        try { console.log("  Method: " + this.getRequestMethod()); } catch (e) {}
                    }
                } catch (e) {}
                try {
                    if (typeof originalConnect === 'function') return originalConnect.apply(this, arguments);
                    return this.connect();
                } catch (e) {
                    try { return this.connect(); } catch (e2) { return null; }
                }
            };
            console.log(colors.green + "[+] Hooked HttpURLConnection" + colors.reset);
        } catch (e) {}
    }

    function hookSharedPreferences() {
        console.log(colors.cyan + "\n[DISCOVERY] Hooking SharedPreferences reads..." + colors.reset);
        try {
            var SharedPreferences = Java.use("android.content.SharedPreferences");
            try {
                var origGetString = SharedPreferences.getString.overload('java.lang.String','java.lang.String');
                var savedGetString = origGetString.implementation;
                origGetString.implementation = function (key, defValue) {
                    var ret;
                    try {
                        if (typeof savedGetString === 'function') ret = savedGetString.apply(this, arguments);
                        else ret = this.getString(key, defValue);
                    } catch (e) { try { ret = this.getString(key, defValue); } catch (e2) { ret = null; } }
                    try {
                        if (key && (key.toLowerCase().indexOf("sentry") !== -1 || key.toLowerCase().indexOf("track") !== -1 || key.toLowerCase().indexOf("analytics") !== -1 || key.toLowerCase().indexOf("health") !== -1)) {
                            console.log(colors.cyan + "\n[PREFS READ] " + colors.reset + key + " = " + ret);
                        }
                    } catch (e) {}
                    return ret;
                };
            } catch (e) {}

            try {
                var origGetBool = SharedPreferences.getBoolean.overload('java.lang.String','boolean');
                var savedGetBool = origGetBool.implementation;
                origGetBool.implementation = function (key, defValue) {
                    var ret;
                    try {
                        if (typeof savedGetBool === 'function') ret = savedGetBool.apply(this, arguments);
                        else ret = this.getBoolean(key, defValue);
                    } catch (e) { try { ret = this.getBoolean(key, defValue); } catch (e2) { ret = defValue; } }
                    try {
                        if (key && (key.toLowerCase().indexOf("sentry") !== -1 || key.toLowerCase().indexOf("track") !== -1 || key.toLowerCase().indexOf("analytics") !== -1 || key.toLowerCase().indexOf("health") !== -1)) {
                            console.log(colors.cyan + "\n[PREFS READ] " + colors.reset + key + " = " + ret);
                        }
                    } catch (e) {}
                    return ret;
                };
            } catch (e) {}
            console.log(colors.green + "[+] Hooked SharedPreferences" + colors.reset);
        } catch (e) {
            console.log(colors.red + "[-] SharedPreferences hook failed: " + e + colors.reset);
        }
    }

    // GENERATE REPORT with suggestions for targeted patches
    function generateReport() {
        setTimeout(function () {
            console.log("\n" + "=".repeat(80));
            console.log(colors.green + "[DISCOVERY REPORT]" + colors.reset);
            console.log("=".repeat(80));

            console.log(colors.yellow + "\n[*] Total Sentry methods observed: " + sentryMethods.length + colors.reset);
            console.log(colors.yellow + "[*] Total validation points: " + validationPoints.length + colors.reset);
            console.log(colors.red + "[*] Killed operations: " + killed_count + colors.reset);
            console.log(colors.red + "[*] Blocked URLs recorded: " + blocked_urls.length + colors.reset);

            // Print top suspicious methods by count
            var items = [];
            for (var m in discoveryStats) items.push({ method: m, count: discoveryStats[m].count, samples: discoveryStats[m].samples });
            items.sort(function(a,b){ return b.count - a.count; });

            if (items.length > 0) {
                console.log(colors.magenta + "\n[Top observed suspicious methods]" + colors.reset);
                for (var i = 0; i < Math.min(10, items.length); i++) {
                    var it = items[i];
                    console.log("\n " + (i+1) + ". " + it.method + " â€” calls: " + it.count);
                    console.log("    Sample args: " + (it.samples[0] ? safeJson(it.samples[0].args) : "[]"));
                    console.log("    Sample return: " + (it.samples[0] ? it.samples[0].ret : "n/a"));
                    console.log("    Stack sample (truncated):\n" + (it.samples[0] ? (it.samples[0].stack.substring ? it.samples[0].stack.substring(0,300) : it.samples[0].stack) : "[no stack]"));
                }
            } else {
                console.log("\n[No suspicious methods observed yet â€” keep using the app to trigger flows]");
            }

            // Suggested patch snippets for top methods (do not auto-apply)
            if (items.length > 0) {
                console.log(colors.red + "\n[Suggested targeted patch snippets]" + colors.reset);
                for (var j = 0; j < Math.min(5, items.length); j++) {
                    var meth = items[j].method;
                    // Split class and method
                    var lastDot = meth.lastIndexOf(".");
                    var cls = (lastDot !== -1) ? meth.substring(0, lastDot) : meth;
                    var mname = (lastDot !== -1) ? meth.substring(lastDot+1) : "METHOD";
                    console.log("\n--- Suggestion #" + (j+1) + " ---");
                    console.log("Class: " + cls);
                    console.log("Method: " + mname);
                    console.log("Patch snippet (copy into your patches section):\n");
                    console.log("try {\n    var C = Java.use('" + cls + "');\n    try {\n        C." + mname + ".overload(/*add arg types or try without overload*/).implementation = function() {\n            // neuter or return safe value\n            console.log('[ðŸ’€ TARGETED NEUTER] " + meth + "');\n            // adjust returned value type as needed\n            return /*safe return value*/;\n        };\n    } catch (e) {}\n} catch (e) {}\n");
                }
                console.log(colors.yellow + "\n[Note] Suggestions are conservative â€” review return types before applying.\n" + colors.reset);
            }

            // print blocked urls summary
            if (blocked_urls.length > 0) {
                console.log(colors.red + "\n[Blocked URLs sample]" + colors.reset);
                for (var k = 0; k < Math.min(10, blocked_urls.length); k++) console.log("  - " + blocked_urls[k]);
            }

            console.log("\n" + "=".repeat(80));
            console.log(colors.cyan + "[*] Keep using the app to surface more checks. Use suggestions for safe targeted patches." + colors.reset);
            console.log("=".repeat(80) + "\n");
        }, 60000); // report after 60s
    }

    // -----------------------------
    // Startup: run patches then discovery hooks
    // -----------------------------
    setTimeout(function () {
        patchSentryFunctions(); // destructive patches
        // Discovery / recorder (safe)
        hookSentryClasses();
        hookValidationMethods();
        hookNetworkCalls();
        hookSharedPreferences();
        generateReport();
    }, 2000);

    console.log(colors.green + "\n[*] All hooks WILL be activated in 2 seconds..." + colors.reset);
    console.log(colors.yellow + "[*] Use the app normally and trigger suspicious flows (registrations, captcha, phone/photo verifications) to gather data." + colors.reset);
});
