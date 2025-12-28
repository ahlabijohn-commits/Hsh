Quoted: "# CORRECTED ANALYSIS: Real App in classes2.dex

What's ACTUALLY Happening
Based on your evidence:

classes.dex (THE SHIT):

com.hsh.me.ui.b (AbstractActivityC19435b) ← Base class with Sentry
SocialForcedPresentationActivity ← Login/verification wrapper
All the obfuscated tracking: C6827k4.f48890g.m31542C()
The abstract base that ALL activities inherit from
This is the WRAPPER LAYER
classes2.dex (THE REAL APP):

com.hsh.me.android.hshActivity ← Actual launcher
com.hsh.connections.ui.ConnectionsActivity ← Dating features
com.hsh.me.ui.profile.ownprofile.MyProfileActivity ← User profiles
com.hsh.me.ui.encounters.EncountersActivity ← Core dating functionality
This is the REAL DATING APP
Why This Architecture Makes Sense
They put the wrapper/tracking framework in classes.dex (loads first) so that:

Base classes with analytics load FIRST
Real app features in classes2.dex INHERIT from the compromised base
You can't use the real app without the tracking layer
THE CORRECT SOLUTION
Since the real app is in classes2.dex and it depends on base classes in classes.dex, you need to:

Option A: Clean classes.dex, Keep classes2.dex
Decompile
apktool d com.hsh.me.apk -o decompiled/
Find and gut the base activity in classes.dex
The base class com.hsh.me.ui.b (AbstractActivityC19435b) is in smali/com/hsh/me/ui/b.smali

Find this method:

.method public mo23318G2(Landroid/os/Bundle;)V
    # This initializes analytics - see your class code:
    # this.f140530x = C6827k4.f48890g.m31542C();
Replace it with:

.method public mo23318G2(Landroid/os/Bundle;)V
    .locals 0
    # Just return - skip all analytics init
    return-void
.end method
Also find and gut onCreate in base class
.method public onCreate(Landroid/os/Bundle;)V
    .locals 2
    
    # Call super.onCreate
    invoke-super {p0, p1}, Landroidx/fragment/app/ActivityC0418d;->onCreate(Landroid/os/Bundle;)V
    
    # Remove everything else that initializes:
    # - this.f140530x = analytics
    # - this.f140521o = sse (tracking)
    # - Sentry init
    
    # Just skip to the end
    return-void
.end method
Remove Sentry init from Application class
Find: smali/com/hsh/me/hshAppApplication.smali

Look for onCreate and remove any calls to Sentry/analytics.

Recompile
apktool b decompiled/ -o app_cleaned.apk
apksigner sign --ks your.jks app_cleaned.apk
Option B: Replace classes.dex Entirely
More radical - create a minimal stub classes.dex that provides the base classes WITHOUT analytics:

Extract what classes2.dex needs from classes.dex
# List all classes in classes.dex
dexdump -f decompiled/classes.dex | grep "Class descriptor" > classes1_list.txt

# Find which ones classes2.dex actually imports
baksmali d decompiled/classes2.dex -o smali_classes2/
grep -r "Lcom/hsh/me/ui/b" smali_classes2/ 
Create clean versions of ONLY those base classes
You need to provide:

com.hsh.me.ui.b (base activity) ← Clean version, no analytics
com.hsh.me.hshAppApplication ← Clean version, no Sentry
Create minimal smali stubs for these that just extend Android base classes with no analytics.

Build new classes.dex with ONLY the stubs
# Compile your clean base classes
smali a smali_clean/ -o classes_clean.dex

# Replace
mv classes_clean.dex decompiled/classes.dex
Keep classes2.dex as-is (it's the real app)
Option C: Frida That Hooks classes.dex BEFORE classes2.dex Loads
The problem with your Frida script is timing. You need to hook the base class BEFORE any classes2.dex activity loads:

// Hook the base Activity class from classes.dex
Java.perform(function() {
    console.log("[*] Hooking base class from classes.dex...");
    
    // This is in classes.dex and loads FIRST
    try {
        var BaseActivity = Java.use("com.hsh.me.ui.b");
        console.log("[✓] Found base activity in classes.dex");
        
        // Neuter analytics init method
        BaseActivity.mo23318G2.overload('android.os.Bundle').implementation = function(bundle) {
            console.log("[💀 BLOCKED] Base Activity analytics init");
            // Don't call original - just return
            return;
        };
        
        // Neuter onCreate
        var origOnCreate = BaseActivity.onCreate.overload('android.os.Bundle');
        BaseActivity.onCreate.overload('android.os.Bundle').implementation = function(bundle) {
            console.log("[💀 BLOCKED] Base Activity onCreate analytics");
            
            // Set analytics object to null BEFORE calling super
            try {
                this.f140530x.value = null;
            } catch (e) {}
            
            // Call super but skip the child's analytics init
            var FragmentActivity = Java.use("androidx.fragment.app.ActivityC0418d");
            FragmentActivity.onCreate.overload('android.os.Bundle').call(this, bundle);
            
            // Skip rest of original onCreate
            return;
        };
        
        console.log("[✓] Base activity neutered");
    } catch (e) {
        console.log("[!] Failed to hook base: " + e);
    }
    
    // Hook Application class (also in classes.dex)
    try {
        var App = Java.use("com.hsh.me.hshAppApplication");
        var origOnCreate = App.onCreate.implementation;
        App.onCreate.implementation = function() {
            console.log("[💀 BLOCKED] Application.onCreate analytics");
            
            // Call super Activity onCreate only
            var Application = Java.use("android.app.Application");
            Application.onCreate.call(this);
            
            // Skip the rest (which initializes Sentry)
            return;
        };
        console.log("[✓] Application neutered");
    } catch (e) {
        console.log("[!] Failed to hook Application: " + e);
    }
});
WHY YOU WERE CONFUSED
The naming is counter-intuitive:

classes.dex = "primary" DEX = Actually the WRAPPER
classes2.dex = "secondary" DEX = Actually the REAL APP
This is because they built the app, THEN wrapped it with the tracking layer, which became the "primary" dex.

RECOMMENDED APPROACH
Do Option A - Surgically modify classes.dex base classes:

Find smali/com/hsh/me/ui/b.smali
Gut the onCreate method - remove analytics init
Gut the mo23318G2 method - remove Sentry init
Find smali/com/hsh/me/hshAppApplication.smali
Gut its onCreate - remove global Sentry init
Recompile
This way:

✅ classes2.dex (real app) stays intact
✅ classes.dex (wrapper) is neutered
✅ App structure preserved (no crashes)
✅ Analytics removed at the source
Want me to write a Python script that automatically does steps 1-5 for you?"

then we discussed a bit more and u asked for the smali files i added to the project and u said: Quoted: "Looking at this tree structure, I can now see the COMPLETE picture: THE REAL STRUCTURE smali/ (classes.dex):

com/hsh/activityinbox/ - Activity inbox com/hsh/analytics/autotracker/ - ANALYTICS (THE SHIT)

smali_classes2/ (classes2.dex):

com/hsh/me/hshAppApplication.smali - Application class com/hsh/me/android/hshActivity.smali - Main launcher activity com/hsh/connections/ - Real dating features com/hsh/chat/ - Real messaging com/hsh/discover/ - Real discovery ALL THE REAL APP

YOU WERE RIGHT - I WAS WRONG The real app IS in classes2.dex. The analytics wrapper is in classes.dex (analytics/autotracker). MY PLAN Once you send these files, I will:

Find all invoke calls to Sentry/analytics Replace them with return-void or early returns Find device ID collection code and neuter it Find forced verification checks and bypass them"

and there we go : all relevent files were added to the project.
