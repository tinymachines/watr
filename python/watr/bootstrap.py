#!/usr/bin/env python3
"""
WATR Bootstrap - WiFi and Bluetooth Adapter Detection and Configuration

This module provides utilities to detect and configure wireless adapters
on Raspberry Pi systems for use with WATR protocol development.
"""

import subprocess
import json
import re
import time
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

@dataclass
class WiFiAdapter:
    """WiFi adapter information"""
    interface: str
    phy: str
    driver: str
    usb_id: Optional[str]
    supports_monitor: bool
    is_onboard: bool
    rfkill_id: Optional[int]
    
@dataclass
class BluetoothAdapter:
    """Bluetooth adapter information"""
    interface: str
    address: str
    rfkill_id: Optional[int]
    is_onboard: bool

class AdapterBootstrap:
    """Bootstrap utility for detecting and configuring wireless adapters"""
    
    def __init__(self):
        self.wifi_adapters: List[WiFiAdapter] = []
        self.bluetooth_adapters: List[BluetoothAdapter] = []
        
    def run_command(self, cmd: str, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
        """Run a shell command and return the result"""
        try:
            result = subprocess.run(
                cmd, 
                shell=True, 
                capture_output=capture,
                text=True,
                check=check
            )
            return result
        except subprocess.CalledProcessError as e:
            if check:
                raise
            return e
    
    def get_rfkill_info(self) -> Dict[str, dict]:
        """Get rfkill information for all devices"""
        result = self.run_command("/usr/sbin/rfkill -J", check=False)
        if result.returncode != 0:
            # Fallback to text output
            result = self.run_command("/usr/sbin/rfkill")
            rfkill_info = {}
            for line in result.stdout.strip().split('\n')[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 4:
                    device_id = int(parts[0])
                    device_type = parts[1]
                    device_name = parts[2]
                    rfkill_info[device_name] = {
                        'id': device_id,
                        'type': device_type,
                        'soft': parts[3] == 'blocked',
                        'hard': parts[4] == 'blocked' if len(parts) > 4 else False
                    }
            return rfkill_info
        
        try:
            data = json.loads(result.stdout)
            rfkill_info = {}
            for item in data.get('', []):
                rfkill_info[item['device']] = {
                    'id': item['id'],
                    'type': item['type'],
                    'soft': item['soft'] == 'blocked',
                    'hard': item['hard'] == 'blocked'
                }
            return rfkill_info
        except json.JSONDecodeError:
            return {}
    
    def get_network_interfaces(self) -> List[str]:
        """Get all network interfaces"""
        result = self.run_command("ip link show")
        interfaces = []
        for line in result.stdout.split('\n'):
            if ': ' in line and not line.startswith(' '):
                interface = line.split(': ')[1].split('@')[0]
                if interface.startswith('wl') or interface.startswith('wlan'):
                    interfaces.append(interface)
        return interfaces
    
    def get_phy_info(self, interface: str) -> Optional[str]:
        """Get the phy device for a network interface"""
        try:
            result = self.run_command(f"/usr/sbin/iw dev {interface} info", check=False)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'wiphy' in line:
                        return f"phy{line.split('wiphy')[1].strip()}"
        except:
            pass
        return None
    
    def get_driver_info(self, interface: str) -> Tuple[Optional[str], Optional[str]]:
        """Get driver and USB ID information for an interface"""
        try:
            # Get driver info
            driver_path = Path(f"/sys/class/net/{interface}/device/driver")
            if driver_path.exists():
                driver = driver_path.resolve().name
            else:
                driver = None
            
            # Get USB ID if it's a USB device
            usb_id = None
            device_path = Path(f"/sys/class/net/{interface}/device")
            if device_path.exists():
                # Look for USB vendor/product IDs
                for parent in device_path.parents:
                    vendor_file = parent / "idVendor"
                    product_file = parent / "idProduct"
                    if vendor_file.exists() and product_file.exists():
                        vendor = vendor_file.read_text().strip()
                        product = product_file.read_text().strip()
                        usb_id = f"{vendor}:{product}"
                        break
            
            return driver, usb_id
        except:
            return None, None
    
    def test_monitor_mode(self, interface: str) -> bool:
        """Test if an interface supports monitor mode"""
        try:
            # First, try to get supported modes from phy info
            phy = self.get_phy_info(interface)
            if phy:
                result = self.run_command(f"/usr/sbin/iw phy {phy} info", check=False)
                if result.returncode == 0 and 'monitor' in result.stdout:
                    # Interface claims to support monitor mode, test it practically
                    return self._test_monitor_mode_practical(interface)
            return False
        except Exception as e:
            print(f"      ⚠️  Error testing monitor mode: {e}")
            return False
    
    def _test_monitor_mode_practical(self, interface: str) -> bool:
        """Practically test monitor mode by trying to set it"""
        try:
            print(f"      Testing monitor mode practically on {interface}...")
            
            # Save current state
            result = self.run_command(f"/usr/sbin/iw dev {interface} info", check=False)
            if result.returncode != 0:
                return False
            
            # Get current type
            current_type = "managed"  # default assumption
            for line in result.stdout.split('\n'):
                if 'type' in line:
                    current_type = line.split('type')[1].strip()
                    break
            
            # Try to set monitor mode
            self.run_command(f"sudo ip link set {interface} down", check=False)
            result = self.run_command(f"sudo /usr/sbin/iw dev {interface} set type monitor", check=False)
            
            if result.returncode == 0:
                print(f"      ✓ Monitor mode test successful")
                # Success! Now restore original mode
                self.run_command(f"sudo /usr/sbin/iw dev {interface} set type {current_type}", check=False)
                self.run_command(f"sudo ip link set {interface} up", check=False)
                return True
            else:
                print(f"      ✗ Monitor mode test failed: {result.stderr}")
                # Restore interface
                self.run_command(f"sudo ip link set {interface} up", check=False)
                return False
        except Exception as e:
            print(f"      ⚠️  Exception during monitor test: {e}")
            return False
    
    def is_onboard_wifi(self, interface: str, driver: Optional[str], usb_id: Optional[str]) -> bool:
        """Determine if this is the onboard WiFi"""
        # Raspberry Pi onboard WiFi typically uses brcmfmac driver
        # and doesn't have a USB ID
        if driver == 'brcmfmac' and usb_id is None:
            return True
        
        # Additional check for built-in devices
        try:
            device_path = Path(f"/sys/class/net/{interface}/device")
            if device_path.exists():
                # Check if it's not under a USB subsystem
                device_str = str(device_path.resolve())
                if 'usb' not in device_str.lower():
                    return True
        except:
            pass
        
        return False
    
    def detect_wifi_adapters(self):
        """Detect all WiFi adapters and their capabilities"""
        print("🔍 Detecting WiFi adapters...")
        
        interfaces = self.get_network_interfaces()
        rfkill_info = self.get_rfkill_info()
        
        for interface in interfaces:
            print(f"  Analyzing {interface}...")
            
            phy = self.get_phy_info(interface)
            driver, usb_id = self.get_driver_info(interface)
            is_onboard = self.is_onboard_wifi(interface, driver, usb_id)
            
            # Get rfkill ID
            rfkill_id = None
            for device, info in rfkill_info.items():
                if info['type'] == 'wlan' and (device == phy or device == interface):
                    rfkill_id = info['id']
                    break
            
            # Test monitor mode (this might take a moment)
            print(f"    Testing monitor mode support...")
            supports_monitor = self.test_monitor_mode(interface)
            
            adapter = WiFiAdapter(
                interface=interface,
                phy=phy or "unknown",
                driver=driver or "unknown",
                usb_id=usb_id,
                supports_monitor=supports_monitor,
                is_onboard=is_onboard,
                rfkill_id=rfkill_id
            )
            
            self.wifi_adapters.append(adapter)
            
            print(f"    ✓ {interface}: {'Onboard' if is_onboard else 'USB'} - "
                  f"Monitor: {'Yes' if supports_monitor else 'No'}")
    
    def detect_bluetooth_adapters(self):
        """Detect Bluetooth adapters"""
        print("🔍 Detecting Bluetooth adapters...")
        
        try:
            # Get Bluetooth interfaces
            result = self.run_command("hciconfig", check=False)
            if result.returncode != 0:
                print("  ⚠️  hciconfig not available, trying alternative method...")
                result = self.run_command("bluetoothctl list", check=False)
            
            rfkill_info = self.get_rfkill_info()
            
            # Parse hciconfig output
            for line in result.stdout.split('\n'):
                if 'hci' in line and ':' in line:
                    # Extract interface name and address
                    parts = line.split()
                    if len(parts) >= 2:
                        interface = parts[0].rstrip(':')
                        address = parts[1] if len(parts) > 1 else "unknown"
                        
                        # Get rfkill ID
                        rfkill_id = None
                        for device, info in rfkill_info.items():
                            if info['type'] == 'bluetooth' and interface in device:
                                rfkill_id = info['id']
                                break
                        
                        adapter = BluetoothAdapter(
                            interface=interface,
                            address=address,
                            rfkill_id=rfkill_id,
                            is_onboard=True  # Assume onboard for now
                        )
                        
                        self.bluetooth_adapters.append(adapter)
                        print(f"    ✓ {interface}: {address}")
                        
        except Exception as e:
            print(f"  ⚠️  Error detecting Bluetooth: {e}")
    
    def unblock_adapters(self):
        """Unblock all wireless adapters"""
        print("🔓 Unblocking wireless adapters...")
        
        try:
            # Unblock all wireless devices
            self.run_command("sudo /usr/sbin/rfkill unblock wifi", check=False)
            self.run_command("sudo /usr/sbin/rfkill unblock bluetooth", check=False)
            
            # Wait a moment for devices to come up
            time.sleep(2)
            
            print("  ✓ All adapters unblocked")
        except Exception as e:
            print(f"  ⚠️  Error unblocking adapters: {e}")
    
    def print_summary(self):
        """Print a summary of detected adapters"""
        print("\n" + "="*60)
        print("📡 WATR ADAPTER BOOTSTRAP SUMMARY")
        print("="*60)
        
        print(f"\n🔌 WiFi Adapters ({len(self.wifi_adapters)} found):")
        for adapter in self.wifi_adapters:
            status = "🟢" if adapter.supports_monitor else "🔴"
            hw_type = "📟 Onboard" if adapter.is_onboard else "🔌 USB"
            print(f"  {status} {adapter.interface} ({adapter.phy})")
            print(f"      {hw_type} - Driver: {adapter.driver}")
            if adapter.usb_id:
                print(f"      USB ID: {adapter.usb_id}")
            print(f"      Monitor Mode: {'✓ YES' if adapter.supports_monitor else '✗ NO'}")
            if adapter.rfkill_id is not None:
                print(f"      RFKill ID: {adapter.rfkill_id}")
            print()
        
        print(f"📱 Bluetooth Adapters ({len(self.bluetooth_adapters)} found):")
        for adapter in self.bluetooth_adapters:
            print(f"  🔵 {adapter.interface}: {adapter.address}")
            if adapter.rfkill_id is not None:
                print(f"      RFKill ID: {adapter.rfkill_id}")
            print()
        
        # Recommendations
        print("💡 RECOMMENDATIONS:")
        monitor_adapters = [a for a in self.wifi_adapters if a.supports_monitor]
        if monitor_adapters:
            best_adapter = monitor_adapters[0]  # Could be smarter about selection
            print(f"  🎯 Use {best_adapter.interface} for monitor mode operations")
            print(f"  📡 Configure {best_adapter.interface} for packet injection/sniffing")
        else:
            print("  ⚠️  No monitor mode capable adapters found!")
            print("  💭 Consider adding a USB WiFi adapter that supports monitor mode")
        
        if self.bluetooth_adapters:
            bt_adapter = self.bluetooth_adapters[0]
            print(f"  📶 Bluetooth available on {bt_adapter.interface}")
        
        print("\n" + "="*60)

def main():
    """Main bootstrap function"""
    print("🚀 WATR Adapter Bootstrap")
    print("Detecting and configuring wireless adapters...\n")
    
    bootstrap = AdapterBootstrap()
    
    try:
        # Detect adapters
        bootstrap.detect_wifi_adapters()
        bootstrap.detect_bluetooth_adapters()
        
        # Unblock adapters
        bootstrap.unblock_adapters()
        
        # Print summary
        bootstrap.print_summary()
        
        # Export configuration for other tools
        config = {
            'wifi_adapters': [
                {
                    'interface': a.interface,
                    'phy': a.phy,
                    'driver': a.driver,
                    'usb_id': a.usb_id,
                    'supports_monitor': a.supports_monitor,
                    'is_onboard': a.is_onboard,
                    'rfkill_id': a.rfkill_id
                }
                for a in bootstrap.wifi_adapters
            ],
            'bluetooth_adapters': [
                {
                    'interface': a.interface,
                    'address': a.address,
                    'rfkill_id': a.rfkill_id,
                    'is_onboard': a.is_onboard
                }
                for a in bootstrap.bluetooth_adapters
            ]
        }
        
        # Save configuration
        with open('/tmp/watr_adapters.json', 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"📄 Configuration saved to /tmp/watr_adapters.json")
        
    except KeyboardInterrupt:
        print("\n⚠️  Bootstrap interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Bootstrap failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()