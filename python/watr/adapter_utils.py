"""
WATR Adapter Utilities

Helper functions for working with wireless adapters detected by bootstrap.
"""

import json
import subprocess
import time
from pathlib import Path
from typing import Optional, Dict, List
from .bootstrap import WiFiAdapter, BluetoothAdapter

class AdapterManager:
    """Manages wireless adapter configuration and operations"""
    
    def __init__(self, config_path: str = "/tmp/watr_adapters.json"):
        self.config_path = config_path
        self.config = self.load_config()
        
    def load_config(self) -> Dict:
        """Load adapter configuration from JSON file"""
        try:
            with open(self.config_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {'wifi_adapters': [], 'bluetooth_adapters': []}
    
    def run_command(self, cmd: str, check: bool = True) -> subprocess.CompletedProcess:
        """Run a shell command"""
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check)
    
    def get_monitor_capable_adapter(self) -> Optional[Dict]:
        """Get the first WiFi adapter that supports monitor mode"""
        for adapter in self.config['wifi_adapters']:
            if adapter['supports_monitor']:
                return adapter
        return None
    
    def get_onboard_adapter(self) -> Optional[Dict]:
        """Get the onboard WiFi adapter"""
        for adapter in self.config['wifi_adapters']:
            if adapter['is_onboard']:
                return adapter
        return None
    
    def get_usb_adapter(self) -> Optional[Dict]:
        """Get the first USB WiFi adapter"""
        for adapter in self.config['wifi_adapters']:
            if not adapter['is_onboard']:
                return adapter
        return None
    
    def set_monitor_mode(self, interface: str) -> bool:
        """Set an interface to monitor mode"""
        try:
            print(f"Setting {interface} to monitor mode...")
            
            # Take interface down
            self.run_command(f"sudo ip link set {interface} down")
            
            # Set monitor mode
            self.run_command(f"sudo iw dev {interface} set type monitor")
            
            # Bring interface up
            self.run_command(f"sudo ip link set {interface} up")
            
            print(f"✓ {interface} is now in monitor mode")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to set monitor mode on {interface}: {e}")
            return False
    
    def set_managed_mode(self, interface: str) -> bool:
        """Set an interface to managed mode"""
        try:
            print(f"Setting {interface} to managed mode...")
            
            # Take interface down
            self.run_command(f"sudo ip link set {interface} down")
            
            # Set managed mode
            self.run_command(f"sudo iw dev {interface} set type managed")
            
            # Bring interface up
            self.run_command(f"sudo ip link set {interface} up")
            
            print(f"✓ {interface} is now in managed mode")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to set managed mode on {interface}: {e}")
            return False
    
    def set_channel(self, interface: str, channel: int) -> bool:
        """Set WiFi channel for an interface"""
        try:
            print(f"Setting {interface} to channel {channel}...")
            self.run_command(f"sudo iw dev {interface} set channel {channel}")
            print(f"✓ {interface} is now on channel {channel}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to set channel on {interface}: {e}")
            return False
    
    def get_interface_info(self, interface: str) -> Dict:
        """Get detailed information about an interface"""
        try:
            result = self.run_command(f"iw dev {interface} info", check=False)
            if result.returncode == 0:
                info = {}
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if 'type' in line:
                        info['type'] = line.split('type')[1].strip()
                    elif 'channel' in line:
                        info['channel'] = line.split('channel')[1].split()[0]
                    elif 'wiphy' in line:
                        info['wiphy'] = line.split('wiphy')[1].strip()
                return info
        except:
            pass
        return {}
    
    def start_monitor_session(self, interface: str = None, channel: int = 6) -> bool:
        """Start a monitor mode session on the best available adapter"""
        if interface is None:
            adapter = self.get_monitor_capable_adapter()
            if not adapter:
                print("❌ No monitor-capable adapter found!")
                return False
            interface = adapter['interface']
        
        print(f"🎯 Starting monitor session on {interface}...")
        
        # Set monitor mode
        if not self.set_monitor_mode(interface):
            return False
        
        # Set channel
        if not self.set_channel(interface, channel):
            return False
        
        print(f"✓ Monitor session active on {interface}, channel {channel}")
        return True
    
    def stop_monitor_session(self, interface: str = None) -> bool:
        """Stop monitor mode session and return to managed mode"""
        if interface is None:
            adapter = self.get_monitor_capable_adapter()
            if not adapter:
                print("❌ No monitor-capable adapter found!")
                return False
            interface = adapter['interface']
        
        print(f"🛑 Stopping monitor session on {interface}...")
        
        # Return to managed mode
        if not self.set_managed_mode(interface):
            return False
        
        print(f"✓ Monitor session stopped on {interface}")
        return True
    
    def get_bluetooth_info(self) -> List[Dict]:
        """Get Bluetooth adapter information"""
        return self.config['bluetooth_adapters']
    
    def enable_bluetooth(self) -> bool:
        """Enable Bluetooth adapter"""
        try:
            print("🔵 Enabling Bluetooth...")
            
            # Unblock bluetooth
            self.run_command("sudo rfkill unblock bluetooth")
            
            # Start bluetooth service
            self.run_command("sudo systemctl start bluetooth", check=False)
            
            # Power on the adapter
            self.run_command("sudo hciconfig hci0 up", check=False)
            
            print("✓ Bluetooth enabled")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to enable Bluetooth: {e}")
            return False
    
    def print_status(self):
        """Print current adapter status"""
        print("\n" + "="*50)
        print("📡 WATR ADAPTER STATUS")
        print("="*50)
        
        print("\n🔌 WiFi Adapters:")
        for adapter in self.config['wifi_adapters']:
            interface = adapter['interface']
            info = self.get_interface_info(interface)
            
            status = "🟢" if adapter['supports_monitor'] else "🔴"
            hw_type = "📟" if adapter['is_onboard'] else "🔌"
            
            print(f"  {status} {hw_type} {interface}")
            print(f"      Mode: {info.get('type', 'unknown')}")
            if 'channel' in info:
                print(f"      Channel: {info['channel']}")
            print(f"      Monitor Support: {'Yes' if adapter['supports_monitor'] else 'No'}")
        
        print("\n📱 Bluetooth Adapters:")
        for adapter in self.config['bluetooth_adapters']:
            print(f"  🔵 {adapter['interface']}: {adapter['address']}")
        
        print("\n" + "="*50)

def main():
    """Command-line interface for adapter utilities"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python -m watr.adapter_utils <command> [args]")
        print("Commands:")
        print("  status          - Show adapter status")
        print("  start-monitor   - Start monitor mode session")
        print("  stop-monitor    - Stop monitor mode session")
        print("  enable-bt       - Enable Bluetooth")
        return
    
    manager = AdapterManager()
    command = sys.argv[1]
    
    if command == "status":
        manager.print_status()
    elif command == "start-monitor":
        channel = int(sys.argv[2]) if len(sys.argv) > 2 else 6
        manager.start_monitor_session(channel=channel)
    elif command == "stop-monitor":
        manager.stop_monitor_session()
    elif command == "enable-bt":
        manager.enable_bluetooth()
    else:
        print(f"Unknown command: {command}")

if __name__ == "__main__":
    main()