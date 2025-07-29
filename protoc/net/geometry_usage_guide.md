# WiFi Geometry Discovery System Usage Guide

## Overview

The WiFi Geometry Discovery system allows WATR nodes to automatically discover their physical relationships by analyzing overlapping WiFi networks. Nodes that see similar WiFi networks are likely physically close to each other.

## Key Features

- **Automatic WiFi Scanning**: Each node periodically scans visible WiFi networks
- **Geometry Analysis**: Nodes share scan data and collectively determine physical clustering
- **LLM Integration**: AI-enhanced analysis of network topology and intelligent behaviors
- **Comprehensive Logging**: All activities are logged for analysis and debugging
- **Location-Aware Messaging**: Nodes can send messages to physically nearby peers

## Setup

### 1. Basic Launch

```bash
# Set environment variables
export WATR_ROOT=/path/to/watr
export WATR_DEVICE=wlan0
export WATR_ADDR=aa:bb:cc:dd:ee:ff
export WATR_NAME="Kitchen-Node"
export WATR_LOCATION="Kitchen"
export WATR_LLM="qwen3:0.6b"

# Launch using the wrapper script
./watr-geometry.sh
```

### 2. Multi-Node Example

Start nodes in different physical locations:

```bash
# Terminal 1 - Kitchen
export WATR_ADDR=aa:bb:cc:dd:ee:01
export WATR_NAME="Kitchen-Node"
export WATR_LOCATION="Kitchen"
./watr-geometry.sh

# Terminal 2 - Living Room  
export WATR_ADDR=aa:bb:cc:dd:ee:02
export WATR_NAME="LivingRoom-Node"
export WATR_LOCATION="Living Room"
./watr-geometry.sh

# Terminal 3 - Garage
export WATR_ADDR=aa:bb:cc:dd:ee:03
export WATR_NAME="Garage-Node"
export WATR_LOCATION="Garage"
./watr-geometry.sh

# Terminal 4 - Office (different building)
export WATR_ADDR=aa:bb:cc:dd:ee:04
export WATR_NAME="Office-Node"
export WATR_LOCATION="Office Building B"
./watr-geometry.sh
```

## Configuration

### Environment Variables

- `WATR_LOCATION`: Human-readable location hint (e.g., "Building-A-Floor-2")
- `WATR_SCAN_INTERVAL`: Seconds between WiFi scans (default: 180)
- `WATR_LOGLEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)

### Scan Intervals

- Default: 180 seconds (3 minutes)
- Minimum recommended: 60 seconds
- For testing: 30-60 seconds
- For production: 180-300 seconds

## Understanding the Output

### 1. Geometry Updates

```
🗺️  === GEOMETRY UPDATE ===
Confidence: 0.75
Clusters: 2
  Cluster 1: ['aa:bb:cc...', 'aa:bb:cc...']  # Kitchen & Living Room
  Cluster 2: ['aa:bb:cc...']                  # Garage
Node Similarities:
  aa:bb:cc... ↔ aa:bb:cc...: 0.823
Distance Estimates:
  aa:bb:cc... ↔ aa:bb:cc...: ~2.0 units      # Same building
  aa:bb:cc... ↔ aa:bb:cc...: Very far        # Different buildings
```

### 2. Confidence Levels

- **0.0-0.3**: Low confidence - need more data
- **0.3-0.5**: Moderate - basic clustering possible
- **0.5-0.7**: Good - reliable geometry estimates
- **0.7-1.0**: Excellent - high-quality topology

### 3. Distance Interpretations

- **1.0**: Very close (same room)
- **2.0**: Close (adjacent rooms)
- **5.0**: Medium (same floor/building)
- **10.0**: Far (different floors)
- **inf**: Very far (different buildings)

## Log Analysis

### Key Log Files

```
logs/
├── <node_name>_watr_node.log           # Node lifecycle
├── <node_name>_watr_handlers.log       # Handler operations
├── <node_name>_watr_llm.log            # LLM interactions
├── <node_name>_watr_network_events.log # Network-wide events
└── <node_name>_*.json                  # JSON formatted logs
```

### Important Log Events

1. **WiFi Scans**: Look for "WiFi scan completed"
2. **Geometry Updates**: Search for "geometry_updated"
3. **Cluster Formation**: Look for "geometry_analysis"
4. **Location Messages**: Search for "[Cluster message]"

## Applications

### 1. Emergency Communication
Nodes automatically identify physically close peers for reliable emergency relay.

### 2. Distributed Sensing
Nodes in the same location can coordinate sensor readings.

### 3. Location-Aware Routing
Messages can be routed through physically optimal paths.

### 4. Cluster Coordination
Nodes in the same physical area can form sub-networks.

## Troubleshooting

### No Geometry Detected

1. Ensure WiFi is enabled: `nmcli radio wifi on`
2. Check nmcli is installed: `which nmcli`
3. Verify different locations have different WiFi environments
4. Wait for at least 2-3 scan cycles

### Low Confidence

1. Spread nodes further apart physically
2. Ensure nodes are in areas with WiFi coverage
3. Check scan intervals aren't too long
4. Verify all nodes are scanning successfully

### Permission Issues

The system requires sudo for:
- Raw socket access (802.11 frames)
- WiFi scanning via nmcli

## Best Practices

1. **Node Placement**: Place nodes in distinctly different WiFi environments
2. **Location Hints**: Always provide meaningful location hints
3. **Scan Timing**: Use appropriate scan intervals for your use case
4. **Log Monitoring**: Monitor logs to understand network behavior
5. **Cluster Size**: 3-5 nodes per physical location works well

## Advanced Usage

### Custom Geometry Callbacks

Add custom handlers for geometry updates in your code:

```python
def my_geometry_handler(geometry: GeometryEstimate):
    if geometry.confidence > 0.6:
        # Your custom logic here
        pass

wifi_handler.add_geometry_callback(my_geometry_handler)
```

### Querying Geometry

Other nodes can query for geometry information:

```python
node.send_message('geometry_query', {'type': 'summary'})
```