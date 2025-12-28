#!/usr/bin/env python3
"""
Sentry Library Binary Patcher
Permanently patches native libraries to disable tracking functionality
For educational and privacy research purposes only
Requirements:
    pip install lief
Usage:
    python3 sentry_patcher.py <input_apk_or_lib> <output_file>
"""

import sys
import os
import lief
from pathlib import Path

class SentryPatcher:
    """Patches Sentry native libraries by replacing function entry points with RET"""
    
    # ARM64 RET instruction: 0xC0 0x03 0x5F 0xD6
    ARM64_RET = bytes([0xC0, 0x03, 0x5F, 0xD6])
    
    # ARMv7 BX LR instruction: 0x1E 0xFF 0x2F 0xE1
    ARM32_RET = bytes([0x1E, 0xFF, 0x2F, 0xE1])
    
    # x86_64 RET instruction: 0xC3
    X86_64_RET = bytes([0xC3])
    
    # Target functions to neutralize
    TARGET_FUNCTIONS = [
        # Core init functions (highest priority)
        "sentry_init",
        "sentry_reinstall_backend",
        "sentry_start_session",
        
        # Transaction/span functions
        "sentry_transaction_start",
        "sentry_transaction_start_ts",
        "sentry_transaction_start_child",
        "sentry_transaction_finish",
        "sentry_span_start_child",
        
        # Capture functions
        "sentry_capture_event",
        "sentry_capture_exception",
        "sentry_capture_message",
        "sentry_captureException",
        "sentry_captureMessage",
        
        # Data collection
        "sentry_add_breadcrumb",
        "sentry_set_transaction",
        "sentry_set_context",
        "sentry_set_tag",
        "sentry_set_extra",
        
        # Network/transport
        "sentry_envelope_serialize",
        "sentry_envelope_write_to_file",
        "sentry_transport_send_envelope",
        
        # Android specific
        "SentryAndroid_init",
        "SentryNdk_init",
        
        # JNI entry point
        "JNI_OnLoad",
    ]
    
    def __init__(self, input_path, output_path):
        self.input_path = Path(input_path)
        self.output_path = Path(output_path)
        self.patched_count = 0
        
    def detect_architecture(self, binary):
        """Detect binary architecture and return appropriate RET instruction"""
        arch = binary.header.machine_type
        
        if arch == lief.ELF.ARCH.AARCH64:
            return self.ARM64_RET, "ARM64"
        elif arch == lief.ELF.ARCH.ARM:
            return self.ARM32_RET, "ARM32"
        elif arch == lief.ELF.ARCH.x86_64:
            return self.X86_64_RET, "x86_64"
        else:
            raise ValueError(f"Unsupported architecture: {arch}")
    
    def patch_function(self, binary, func_name, ret_instruction):
        """Patch a single function to immediately return"""
        try:
            # Try to find exported symbol
            symbol = binary.get_symbol(func_name)
            if not symbol:
                return False
            
            offset = symbol.value
            if offset == 0:
                return False
            
            # Get the section containing this address
            section = binary.section_from_virtual_address(offset)
            if not section:
                return False
            
            # Calculate offset within section
            section_offset = offset - section.virtual_address
            
            # Get section content
            content = bytearray(section.content)
            
            # Patch with RET instruction
            for i, byte in enumerate(ret_instruction):
                if section_offset + i < len(content):
                    content[section_offset + i] = byte
            
            # Write back
            section.content = list(content)
            
            print(f"  âœ“ Patched: {func_name} @ 0x{offset:08x}")
            return True
            
        except Exception as e:
            print(f"  âœ— Failed to patch {func_name}: {e}")
            return False
    
    def patch_library(self, lib_path):
        """Patch a single library file"""
        print(f"\n[*] Processing: {lib_path}")
        
        try:
            # Parse ELF binary
            binary = lief.parse(str(lib_path))
            if not binary:
                print(f"  âœ— Failed to parse binary")
                return False
            
            # Detect architecture
            ret_instruction, arch = self.detect_architecture(binary)
            print(f"  [i] Architecture: {arch}")
            
            # Patch target functions
            local_patch_count = 0
            for func_name in self.TARGET_FUNCTIONS:
                if self.patch_function(binary, func_name, ret_instruction):
                    local_patch_count += 1
                    self.patched_count += 1
            
            if local_patch_count > 0:
                # Write patched binary
                binary.write(str(self.output_path))
                print(f"  [âœ“] Patched {local_patch_count} functions")
                return True
            else:
                print(f"  [!] No target functions found")
                return False
                
        except Exception as e:
            print(f"  âœ— Error: {e}")
            return False
    
    def patch_apk_libraries(self):
        """Extract and patch libraries from APK"""
        import zipfile
        import tempfile
        import shutil
        
        print(f"[*] Processing APK: {self.input_path}")
        
        # Create temp directory
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Extract APK
            print("[*] Extracting APK...")
            with zipfile.ZipFile(self.input_path, 'r') as zip_ref:
                zip_ref.extractall(temp_path)
            
            # Find all .so files
            lib_dirs = [
                temp_path / "lib",
                temp_path / "lib" / "arm64-v8a",
                temp_path / "lib" / "armeabi-v7a",
            ]
            
            so_files = []
            for lib_dir in lib_dirs:
                if lib_dir.exists():
                    so_files.extend(lib_dir.glob("*.so"))
            
            # Filter for Sentry-related libraries
            sentry_libs = [f for f in so_files if 
                          "sentry" in f.name.lower() or
                          "apminsight" in f.name.lower()]
            
            if not sentry_libs:
                print("[!] No Sentry libraries found in APK")
                return False
            
            print(f"[*] Found {len(sentry_libs)} Sentry libraries")
            
            # Patch each library
            for lib in sentry_libs:
                backup = lib.with_suffix(lib.suffix + ".bak")
                shutil.copy(lib, backup)
                
                temp_output = lib.with_suffix(lib.suffix + ".patched")
                self.output_path = temp_output
                
                if self.patch_library(lib):
                    shutil.move(temp_output, lib)
                    print(f"  [âœ“] Library updated in place")
            
            # Repackage APK
            output_apk = self.input_path.with_suffix(".patched.apk")
            print(f"\n[*] Repackaging APK to: {output_apk}")
            
            with zipfile.ZipFile(output_apk, 'w', zipfile.ZIP_DEFLATED) as zip_out:
                for root, dirs, files in os.walk(temp_path):
                    for file in files:
                        file_path = Path(root) / file
                        arcname = file_path.relative_to(temp_path)
                        zip_out.write(file_path, arcname)
            
            self.output_path = output_apk
            return True
    
    def run(self):
        """Main execution"""
        print("=" * 60)
        print("â˜¢ï¸  SENTRY LIBRARY BINARY PATCHER â˜¢ï¸")
        print("=" * 60)
        
        if not self.input_path.exists():
            print(f"âœ— Input file not found: {self.input_path}")
            return False
        
        # Determine if input is APK or library
        if self.input_path.suffix.lower() == ".apk":
            success = self.patch_apk_libraries()
        elif self.input_path.suffix.lower() == ".so":
            success = self.patch_library(self.input_path)
        else:
            print(f"âœ— Unsupported file type: {self.input_path.suffix}")
            return False
        
        if success:
            print("\n" + "=" * 60)
            print(f"âœ“ PATCHING COMPLETE")
            print(f"âœ“ Total functions patched: {self.patched_count}")
            print(f"âœ“ Output: {self.output_path}")
            print("=" * 60)
            print("\nâš ï¸  Remember to:")
            print("  1. Sign the APK: jarsigner or apksigner")
            print("  2. Zipalign: zipalign -v 4 input.apk output.apk")
            print("  3. Test thoroughly before deployment")
        
        return success


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 sentry_patcher.py <input_apk_or_lib> <output_file>")
        print("\nExamples:")
        print("  python3 sentry_patcher.py app.apk app_patched.apk")
        print("  python3 sentry_patcher.py libsentry.so libsentry_patched.so")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    patcher = SentryPatcher(input_file, output_file)
    success = patcher.run()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
