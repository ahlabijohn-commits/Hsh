#!/usr/bin/env python3
"""
SURGICAL SMALI PATCHER - Nuclear Privacy Solution (Windows Edition)
Patches base classes to neutralize ALL analytics at the root
NO frida needed - permanent patches to APK
"""

import os
import sys
import zipfile
import shutil
import subprocess
from pathlib import Path

class SurgicalPatcher:
    def __init__(self, apk_path):
        self.apk_path = Path(apk_path)
        self.output_dir = Path(r"C:\Users\MTHG\Desktop\Sentry-Patching-Kit")
        self.work_dir = self.output_dir / "decompiled_app"
        self.patches_applied = 0
        
        # Tool paths - already in PATH
        self.apktool = "apktool"
        self.apksigner = r"C:\Users\MTHG\Desktop\Android\APKtool\Resources\apksigner.jar"
        self.zipalign = r"C:\Users\MTHG\Desktop\Android\APKtool\Resources\zipalign.exe"
        self.testkey_pk8 = r"C:\Users\MTHG\Desktop\Android\APKtool\Resources\testkey.pk8"
        self.testkey_pem = r"C:\Users\MTHG\Desktop\Android\APKtool\Resources\testkey.x509.pem"
        
    def sanitize_filename(self, name):
        """Create a safe filename from APK name"""
        # Remove common problematic characters
        safe_name = name.replace(' ', '_').replace('-', '_')
        # Keep only the first part if too long
        if len(safe_name) > 50:
            safe_name = safe_name[:50]
        return safe_name
        
    def decompile(self):
        """Decompile APK with apktool (with increased memory)"""
        print("[*] Decompiling APK...")
        
        # Remove old decompiled folder if exists
        if self.work_dir.exists():
            print("[*] Removing old decompiled files...")
            shutil.rmtree(self.work_dir)
        
        # Use increased Java heap size for large APKs
        # Set _JAVA_OPTIONS environment variable
        env = os.environ.copy()
        env['_JAVA_OPTIONS'] = '-Xmx4096m'  # 4GB heap
        
        cmd = f'{self.apktool} d -f "{self.apk_path}" -o "{self.work_dir}"'
        print(f"[*] Running: {cmd}")
        print("[*] This may take a few minutes for large APKs...")
        
        result = subprocess.run(cmd, shell=True, env=env)
        
        if result.returncode != 0:
            print("[!] Decompilation failed!")
            print("[!] Try increasing Java heap size or use a smaller APK")
            sys.exit(1)
            
        print("[✓] Decompilation complete")
        
    def patch_base_activity(self):
        """Patch AbstractActivityC19435b (classes.dex) - The wrapper all activities inherit"""
        base_activity = self.work_dir / "smali/com/hsh/me/ui/b.smali"
        
        if not base_activity.exists():
            print("[!] Base activity not found (app structure may be different)")
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
            print("[!] Application class not found (app structure may be different)")
            return
            
        print("\n[*] Patching Application class...")
        
        with open(app_class, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # PATCH: Neuter onCreate - this is where Sentry initializes
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
            print("[!] Autotracker not found (app structure may be different)")
            return
            
        print("\n[*] Patching Autotracker...")
        
        with open(autotracker, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Set all tracking flags to FALSE
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
        skip_until_end = False
        
        for line in lines:
            if '.method public constructor <init>(ZZZZZ)V' in line:
                new_lines.extend(new_init.split('\n'))
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
            print("[!] HshActivity not found (app structure may be different)")
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
        # Create safe filename
        safe_name = self.sanitize_filename(self.apk_path.stem)
        output_apk = self.output_dir / f"{safe_name}_Patched.apk"
        output_aligned = self.output_dir / f"{safe_name}_Patched_aligned.apk"
        
        # Remove old output files if they exist
        if output_apk.exists():
            output_apk.unlink()
        if output_aligned.exists():
            output_aligned.unlink()
        
        print("\n[*] Recompiling APK...")
        print("[*] This may take several minutes for large APKs...")
        
        # Use increased Java heap size
        env = os.environ.copy()
        env['_JAVA_OPTIONS'] = '-Xmx4096m'  # 4GB heap
        
        cmd = f'{self.apktool} b "{self.work_dir}" -o "{output_apk}"'
        result = subprocess.run(cmd, shell=True, env=env)
        
        if result.returncode != 0 or not output_apk.exists():
            print("[!] Recompilation failed!")
            print("[!] Check the error messages above")
            print("[!] You may need to increase Java heap size further")
            sys.exit(1)
        
        print("[✓] Recompilation complete")
        
        # Zipalign
        print("[*] Zipaligning APK...")
        cmd = f'"{self.zipalign}" -f -p 4 "{output_apk}" "{output_aligned}"'
        result = subprocess.run(cmd, shell=True)
        
        if result.returncode == 0 and output_aligned.exists():
            # Replace original with aligned version
            output_apk.unlink()
            output_aligned.rename(output_apk)
            print("[✓] Zipalign complete")
        else:
            print("[!] Zipalign failed, continuing with unaligned APK...")
        
        # Sign APK with testkey
        print("[*] Signing APK...")
        
        # First, try with testkey (most reliable method)
        cmd = [
            'java', '-jar', str(self.apksigner),
            'sign',
            '--key', str(self.testkey_pk8),
            '--cert', str(self.testkey_pem),
            '--out', str(output_apk) + '.signed',
            str(output_apk)
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0 and Path(str(output_apk) + '.signed').exists():
            # Replace with signed version
            output_apk.unlink()
            Path(str(output_apk) + '.signed').rename(output_apk)
            print("[✓] Signing complete")
        else:
            print("[!] Signing with testkey failed, trying in-place signing...")
            
            # Try in-place signing
            cmd = [
                'java', '-jar', str(self.apksigner),
                'sign',
                '--key', str(self.testkey_pk8),
                '--cert', str(self.testkey_pem),
                str(output_apk)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                print("[✓] Signing complete")
            else:
                print("[!] Signing failed!")
                print("[!] Error:", result.stderr)
                print("\n[*] APK compiled but unsigned. You can sign it manually:")
                print(f'    java -jar "{self.apksigner}" sign --key "{self.testkey_pk8}" --cert "{self.testkey_pem}" "{output_apk}"')
        
        return output_apk
    
    def cleanup(self):
        """Remove working directory"""
        if self.work_dir.exists():
            print("\n[*] Cleaning up temporary files...")
            try:
                shutil.rmtree(self.work_dir)
                print("[✓] Cleanup complete")
            except Exception as e:
                print(f"[!] Cleanup failed: {e}")
                print("[!] You can manually delete: " + str(self.work_dir))
    
    def run(self):
        """Execute full patching workflow"""
        print("=" * 70)
        print("☢️  SURGICAL SMALI PATCHER - NUCLEAR PRIVACY SOLUTION ☢️")
        print("=" * 70)
        print(f"\nInput APK: {self.apk_path}")
        print(f"Output Directory: {self.output_dir}\n")
        
        if not self.apk_path.exists():
            print(f"[!] ERROR: APK file not found: {self.apk_path}")
            sys.exit(1)
        
        # Check Java memory
        print("[*] Checking Java configuration...")
        result = subprocess.run(['java', '-version'], capture_output=True, text=True)
        print("[✓] Java is installed")
        print("[!] NOTE: Large APKs need 4GB+ RAM. Script will use -Xmx4096m")
        
        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
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
            
            if self.patches_applied > 0:
                print("\n🛡️  Privacy restored at the SOURCE level 🛡️")
            else:
                print("\n⚠️  WARNING: No patches applied!")
                print("   The app structure may be different than expected.")
                print("   The APK was recompiled but analytics may still be active.")
            
            print("\n📱 Install patched APK:")
            print(f'   adb install "{output}"')
            print("\n   Or to replace existing app:")
            print(f'   adb install -r "{output}"')
            
        except KeyboardInterrupt:
            print("\n\n[!] Interrupted by user")
            sys.exit(1)
        except Exception as e:
            print(f"\n[!] ERROR: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
        finally:
            # Clean up temporary files
            self.cleanup()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("=" * 70)
        print("SURGICAL SMALI PATCHER - Windows Edition")
        print("=" * 70)
        print("\nUsage:")
        print('  python smali_patcher.py "C:\\path\\to\\app.apk"')
        print("\nExample:")
        print('  python smali_patcher.py "C:\\Users\\MTHG\\Downloads\\myapp.apk"')
        print("\nOutput will be saved to:")
        print("  C:\\Users\\MTHG\\Desktop\\Sentry-Patching-Kit\\")
        print("  Named as: (sanitized_name)_Patched.apk")
        print("\nNote: Requires 4GB+ RAM for large APKs")
        print("=" * 70)
        sys.exit(1)
    
    patcher = SurgicalPatcher(sys.argv[1])
    patcher.run()