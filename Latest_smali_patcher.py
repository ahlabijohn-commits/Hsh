#!/usr/bin/env python3
"""
SURGICAL SMALI PATCHER - Nuclear Privacy Solution
Patches base classes to neutralize ALL analytics at the root
NO frida needed - permanent patches to APK
"""

import os
import sys
import zipfile
import shutil
from pathlib import Path

class SurgicalPatcher:
    def __init__(self, apk_path):
        self.apk_path = Path(apk_path)
        self.work_dir = Path("./decompiled_app")
        self.patches_applied = 0
        
    def decompile(self):
        """Decompile APK with apktool"""
        print("[*] Decompiling APK...")
        os.system(f"apktool d -f {self.apk_path} -o {self.work_dir}")
        
    def patch_base_activity(self):
        """Patch AbstractActivityC19435b (classes.dex) - The wrapper all activities inherit"""
        base_activity = self.work_dir / "smali/com/hsh/me/ui/b.smali"
        
        if not base_activity.exists():
            print("[!] Base activity not found")
            return
            
        print("\n[*] Patching base activity (THE CRITICAL ONE)...")
        
        with open(base_activity, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # PATCH 1: Neuter G2 (analytics init) - called by ALL activities
        old_g2 = """.method public mo23318G2(Landroid/os/Bundle;)V
    .locals 0

    invoke-super {p0, p1}, Landroidx/fragment/app/ActivityC0418d;->onCreate(Landroid/os/Bundle;)V"""
        
        new_g2 = """.method public mo23318G2(Landroid/os/Bundle;)V
    .locals 0
    
    # NEUTERED: Skip ALL analytics initialization
    return-void"""
        
        if old_g2 in content:
            content = content.replace(old_g2, new_g2)
            self.patches_applied += 1
            print("  ✓ Neutered G2() - Analytics init disabled")
        
        # PATCH 2: Neuter onCreate analytics 
        # Find: this.f140530x = C6827k4.f48890g.m31542C();
        # Replace entire analytics init block with return
        
        old_oncreate_analytics = """invoke-virtual {v0}, Lb/on8;->a()Lb/w3g;

    move-result-object v0

    sget-wide v1, Lb/u03;->k:J

    invoke-interface {v0, v1, v2}, Lb/h61;->c(J)V"""
        
        new_oncreate_analytics = """# NEUTERED: Analytics tracking disabled
    nop
    nop
    nop"""
        
        if old_oncreate_analytics in content:
            content = content.replace(old_oncreate_analytics, new_oncreate_analytics)
            self.patches_applied += 1
            print("  ✓ Neutered onCreate() - Tracking disabled")
        
        # PATCH 3: Neuter onResume analytics (called on EVERY screen view)
        old_resume = """invoke-static {v0, v1, v2}, Lb/iy4;->m15813s(Lb/m9m;Ljava/lang/Object;Lb/lf;)V"""
        new_resume = """# NEUTERED: Screen tracking disabled
    nop"""
        
        if old_resume in content:
            content = content.replace(old_resume, new_resume)
            self.patches_applied += 1
            print("  ✓ Neutered onResume() - Screen tracking disabled")
            
        with open(base_activity, 'w', encoding='utf-8') as f:
            f.write(content)
    
    def patch_application_class(self):
        """Patch HshAppApplication - initializes Sentry"""
        app_class = self.work_dir / "smali_classes2/com/hsh/me/hshAppApplication.smali"
        
        if not app_class.exists():
            print("[!] Application class not found")
            return
            
        print("\n[*] Patching Application class...")
        
        with open(app_class, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # PATCH: Neuter onCreate - this is where Sentry initializes
        old_app_oncreate = """.method public final onCreate()V"""
        new_app_oncreate = """.method public final onCreate()V
    .locals 0
    
    # NEUTERED: Sentry initialization completely disabled
    invoke-super {p0}, Lb/x12;->onCreate()V
    return-void"""
        
        # Find and replace the entire onCreate method body
        lines = content.split('\n')
        new_lines = []
        in_oncreate = False
        skip_until_end_method = False
        
        for line in lines:
            if '.method public final onCreate()V' in line:
                new_lines.append(line)
                new_lines.append('    .locals 0')
                new_lines.append('    ')
                new_lines.append('    # NEUTERED: All analytics disabled')
                new_lines.append('    invoke-super {p0}, Lb/x12;->onCreate()V')
                new_lines.append('    return-void')
                in_oncreate = True
                skip_until_end_method = True
                self.patches_applied += 1
                print("  ✓ Neutered Application.onCreate() - Sentry init blocked")
            elif skip_until_end_method and '.end method' in line:
                new_lines.append(line)
                skip_until_end_method = False
                in_oncreate = False
            elif not skip_until_end_method:
                new_lines.append(line)
        
        with open(app_class, 'w', encoding='utf-8') as f:
            f.write('\n'.join(new_lines))
    
    def patch_autotracker(self):
        """Patch AutotrackerConfiguration - disable tracking config"""
        autotracker = self.work_dir / "smali/com/hsh/analytics/autotracker/AutotrackerConfiguration.smali"
        
        if not autotracker.exists():
            print("[!] Autotracker not found")
            return
            
        print("\n[*] Patching Autotracker...")
        
        with open(autotracker, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Set all tracking flags to FALSE
        old_init = """.method public constructor <init>(ZZZZZ)V"""
        new_init = """.method public constructor <init>(ZZZZZ)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    # NEUTERED: All flags forced to FALSE
    const/4 p1, 0x0
    iput-boolean p1, p0, Lcom/hsh/analytics/autotracker/AutotrackerConfiguration;->a:Z

    const/4 p2, 0x0
    iput-boolean p2, p0, Lcom/hsh/analytics/autotracker/AutotrackerConfiguration;->b:Z

    const/4 p3, 0x0
    iput-boolean p3, p0, Lcom/hsh/analytics/autotracker/AutotrackerConfiguration;->c:Z

    const/4 p4, 0x0
    iput-boolean p4, p0, Lcom/hsh/analytics/autotracker/AutotrackerConfiguration;->d:Z

    const/4 p5, 0x0
    iput-boolean p5, p0, Lcom/hsh/analytics/autotracker/AutotrackerConfiguration;->e:Z

    return-void"""
        
        # Find constructor and replace
        lines = content.split('\n')
        new_lines = []
        in_constructor = False
        skip_until_end = False
        
        for line in lines:
            if '.method public constructor <init>(ZZZZZ)V' in line:
                new_lines.extend(new_init.split('\n'))
                in_constructor = True
                skip_until_end = True
                self.patches_applied += 1
                print("  ✓ Disabled all autotracking flags")
            elif skip_until_end and '.end method' in line:
                new_lines.append(line)
                skip_until_end = False
            elif not skip_until_end:
                new_lines.append(line)
        
        with open(autotracker, 'w', encoding='utf-8') as f:
            f.write('\n'.join(new_lines))
    
    def patch_hsh_activity(self):
        """Patch HshActivity - main launcher"""
        hsh_activity = self.work_dir / "smali_classes2/com/hsh/me/android/hshActivity.smali"
        
        if not hsh_activity.exists():
            print("[!] HshActivity not found")
            return
            
        print("\n[*] Patching HshActivity launcher...")
        
        with open(hsh_activity, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Neuter analytics call in onCreate
        old_analytics = """invoke-interface {v0, v3, v4}, Lb/h61;->c(J)V"""
        new_analytics = """# NEUTERED: Launcher analytics disabled
    nop"""
        
        if old_analytics in content:
            content = content.replace(old_analytics, new_analytics)
            self.patches_applied += 1
            print("  ✓ Disabled launcher tracking")
            
        with open(hsh_activity, 'w', encoding='utf-8') as f:
            f.write(content)
    
    def recompile(self):
        """Recompile and sign APK"""
        output_apk = self.apk_path.parent / f"{self.apk_path.stem}_patched.apk"
        
        print("\n[*] Recompiling APK...")
        os.system(f"apktool b {self.work_dir} -o {output_apk}")
        
        print("[*] Signing APK...")
        # Use uber-apk-signer for automatic signing
        os.system(f"uber-apk-signer -a {output_apk} --allowResign --overwrite")
        
        return output_apk
    
    def cleanup(self):
        """Remove working directory"""
        if self.work_dir.exists():
            shutil.rmtree(self.work_dir)
    
    def run(self):
        """Execute full patching workflow"""
        print("=" * 70)
        print("☢️  SURGICAL SMALI PATCHER - NUCLEAR PRIVACY SOLUTION ☢️")
        print("=" * 70)
        
        try:
            self.decompile()
            self.patch_base_activity()      # MOST CRITICAL
            self.patch_application_class()  # SECOND CRITICAL
            self.patch_autotracker()
            self.patch_hsh_activity()
            
            output = self.recompile()
            
            print("\n" + "=" * 70)
            print(f"✓ PATCHING COMPLETE")
            print(f"✓ Patches applied: {self.patches_applied}")
            print(f"✓ Output: {output}")
            print("=" * 70)
            print("\n🛡️  Privacy restored at the SOURCE level 🛡️")
            print("\nInstall patched APK:")
            print(f"  adb install {output}")
            
        finally:
            # Uncomment to keep files for inspection:
            # self.cleanup()
            pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 surgical_patcher.py app.apk")
        sys.exit(1)
    
    patcher = SurgicalPatcher(sys.argv[1])
    patcher.run()
