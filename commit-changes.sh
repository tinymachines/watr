#!/bin/bash
cd /home/bisenbek/projects/watr
git add -A
git status
git commit -m "Add monitor interface setup to bootstrap utility

- Added --setup-monitor flag to automatically create monitor interface
- Auto-selects best monitor-capable adapter (prefers USB over onboard)
- Creates mon0 interface on channel 1 (2412 MHz) by default
- Added convenience functions for programmatic use
- Updated all documentation with new functionality

Usage:
  python bootstrap.py --setup-monitor
  python bootstrap.py --setup-monitor --adapter wlan1
  python bootstrap.py --setup-monitor --monitor-interface mon1"
git push