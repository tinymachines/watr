#!/usr/bin/env python3
"""
Test the new bootstrap monitor setup functionality
"""
import sys
import subprocess

def test_bootstrap_monitor():
    """Test bootstrap with monitor setup"""
    print("🧪 Testing Bootstrap Monitor Setup")
    print("=" * 50)
    
    # Test 1: Basic detection
    print("\n1️⃣ Testing basic detection...")
    result = subprocess.run([sys.executable, "python/watr/bootstrap.py"], capture_output=True, text=True)
    if result.returncode == 0:
        print("✅ Basic detection works")
    else:
        print(f"❌ Basic detection failed: {result.stderr}")
    
    # Test 2: Help text
    print("\n2️⃣ Testing help...")
    result = subprocess.run([sys.executable, "python/watr/bootstrap.py", "--help"], capture_output=True, text=True)
    if "--setup-monitor" in result.stdout:
        print("✅ Help shows monitor setup option")
    else:
        print("❌ Help missing monitor setup option")
    
    # Test 3: Quick setup function
    print("\n3️⃣ Testing quick setup import...")
    try:
        from watr.bootstrap import setup_monitor_quick, get_monitor_capable_adapter
        print("✅ Functions imported successfully")
        
        # Test getting monitor capable adapter
        adapter = get_monitor_capable_adapter()
        if adapter:
            print(f"✅ Found monitor capable adapter: {adapter}")
        else:
            print("⚠️  No saved adapter info (run bootstrap first)")
            
    except ImportError as e:
        print(f"❌ Import failed: {e}")
    
    print("\n" + "=" * 50)
    print("📝 To test full monitor setup, run:")
    print("   sudo python bootstrap.py --setup-monitor")

if __name__ == "__main__":
    test_bootstrap_monitor()