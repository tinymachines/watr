"""
WiFi-Based Geometry Discovery Handler for WATR Nodes
Uses overlapping WiFi networks to infer relative node positions
Updated with comprehensive logging support
"""

import asyncio
import subprocess
import time
import json
import math
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, asdict
from collections import defaultdict

from watr_handlers import WATRHandler
from watr_protocol import WATRMessage
from watr_logging import WATRLoggerMixin


@dataclass
class WiFiNetwork:
    """Represents a scanned WiFi network"""
    ssid: str
    bssid: str  # MAC address of access point
    signal_strength: int  # dBm
    frequency: int  # MHz
    channel: int
    security: str
    timestamp: float


@dataclass
class NodeScanResult:
    """WiFi scan result from a specific node"""
    node_id: str
    timestamp: float
    networks: List[WiFiNetwork]
    location_hint: Optional[str] = None  # Optional human-readable location


@dataclass
class GeometryEstimate:
    """Estimated geometric relationship between nodes"""
    node_pairs: Dict[Tuple[str, str], float]  # (node1, node2) -> similarity_score
    clusters: List[List[str]]  # Groups of nodes that are likely close together
    distances: Dict[Tuple[str, str], float]  # Estimated relative distances
    confidence: float  # Overall confidence in the geometry estimate


class LoggedWiFiGeometryHandler(WATRHandler, WATRLoggerMixin):
    """WiFi-based geometry discovery with comprehensive logging"""
    
    def __init__(self, node, scan_interval: int = 300, location_hint: str = None):
        WATRLoggerMixin.__init__(self)
        WATRHandler.__init__(self, node)
        
        self.scan_interval = scan_interval  # seconds between scans
        self.location_hint = location_hint  # e.g., "Building A Floor 2"
        
        # Data storage
        self.my_scans: List[NodeScanResult] = []
        self.peer_scans: Dict[str, List[NodeScanResult]] = defaultdict(list)
        self.all_networks: Dict[str, WiFiNetwork] = {}  # bssid -> latest network info
        
        # Geometry analysis
        self.last_geometry: Optional[GeometryEstimate] = None
        self.geometry_callbacks: List[callable] = []
        
        # Tasks
        self.scan_task: Optional[asyncio.Task] = None
        self.analysis_task: Optional[asyncio.Task] = None
        
        self.logger.info(
            "WiFi Geometry Handler initialized",
            extra={
                **self.log_extra,
                'scan_interval': scan_interval,
                'location_hint': location_hint,
                'handled_message_types': self.get_handled_message_types()
            }
        )
    
    def get_handled_message_types(self) -> List[str]:
        return ['wifi_scan', 'geometry_query', 'geometry_response']
    
    async def on_activate(self):
        """Start WiFi scanning and analysis when activated"""
        await super().on_activate()
        
        # Start periodic scanning
        self.scan_task = asyncio.create_task(self._scan_loop())
        
        # Start periodic geometry analysis
        self.analysis_task = asyncio.create_task(self._analysis_loop())
        
        self.logger.info(
            f"WiFi Geometry Discovery activated",
            extra={
                **self.log_extra,
                'scan_interval': self.scan_interval,
                'event_type': 'handler_activated'
            }
        )
    
    async def on_deactivate(self):
        """Stop scanning when deactivated"""
        await super().on_deactivate()
        
        if self.scan_task:
            self.scan_task.cancel()
        if self.analysis_task:
            self.analysis_task.cancel()
            
        self.logger.info(
            "WiFi Geometry Discovery deactivated",
            extra={
                **self.log_extra,
                'event_type': 'handler_deactivated'
            }
        )
    
    async def cleanup(self):
        """Cleanup resources"""
        await self.on_deactivate()
    
    async def handle_message(self, message: WATRMessage) -> None:
        """Handle incoming WiFi scan data and geometry queries"""
        if not self.is_active:
            return
        
        self.log_message_received(message, {'handler_type': 'wifi_geometry'})
        
        try:
            if message.message_type == 'wifi_scan':
                await self._handle_wifi_scan(message)
            elif message.message_type == 'geometry_query':
                await self._handle_geometry_query(message)
            elif message.message_type == 'geometry_response':
                await self._handle_geometry_response(message)
        except Exception as e:
            self.log_error(e, f"handling {message.message_type}", {
                'message_payload': message.payload
            })
    
    async def _handle_wifi_scan(self, message: WATRMessage):
        """Process incoming WiFi scan data from peers"""
        start_time = time.time()
        
        try:
            payload = message.payload
            
            # Reconstruct networks
            networks = []
            for net_data in payload.get('networks', []):
                network = WiFiNetwork(**net_data)
                networks.append(network)
                # Update our global network database
                self.all_networks[network.bssid] = network
            
            # Create scan result
            scan_result = NodeScanResult(
                node_id=message.src_addr,
                timestamp=payload.get('timestamp', message.timestamp),
                networks=networks,
                location_hint=payload.get('location_hint')
            )
            
            # Store peer scan
            self.peer_scans[message.src_addr].append(scan_result)
            
            # Keep only recent scans (last 24 hours)
            cutoff = time.time() - 86400
            self.peer_scans[message.src_addr] = [
                s for s in self.peer_scans[message.src_addr] 
                if s.timestamp > cutoff
            ]
            
            duration = time.time() - start_time
            
            self.logger.info(
                f"Processed WiFi scan from peer",
                extra={
                    **self.log_extra,
                    'peer_addr': message.src_addr,
                    'network_count': len(networks),
                    'location_hint': scan_result.location_hint,
                    'processing_time': duration,
                    'event_type': 'wifi_scan_received'
                }
            )
            
            self.log_performance("process_wifi_scan", duration, {
                'network_count': len(networks),
                'peer_addr': message.src_addr
            })
            
        except Exception as e:
            self.log_error(e, "processing WiFi scan", {
                'src_addr': message.src_addr
            })
    
    async def _handle_geometry_query(self, message: WATRMessage):
        """Handle geometry information requests"""
        query_type = message.payload.get('type', 'summary')
        
        self.logger.debug(
            f"Received geometry query",
            extra={
                **self.log_extra,
                'query_type': query_type,
                'from_peer': message.src_addr
            }
        )
        
        if query_type == 'summary' and self.last_geometry:
            # Send back our current geometry estimate
            response = {
                'type': 'geometry_response',
                'geometry': {
                    'confidence': self.last_geometry.confidence,
                    'cluster_count': len(self.last_geometry.clusters),
                    'node_count': len(set().union(*self.last_geometry.clusters)) if self.last_geometry.clusters else 0,
                    'timestamp': time.time()
                }
            }
            
            self.node.send_message('geometry_response', response, message.src_addr)
            self.log_message_sent('geometry_response', response, message.src_addr)
    
    async def _handle_geometry_response(self, message: WATRMessage):
        """Handle geometry response from peers"""
        self.logger.debug(
            f"Received geometry response",
            extra={
                **self.log_extra,
                'from_peer': message.src_addr,
                'geometry_data': message.payload.get('geometry', {})
            }
        )
    
    async def _scan_loop(self):
        """Periodically scan WiFi networks"""
        scan_count = 0
        
        while self.is_active:
            try:
                scan_count += 1
                start_time = time.time()
                
                # Perform WiFi scan
                networks = await self._scan_wifi()
                scan_duration = time.time() - start_time
                
                if networks:
                    # Create scan result
                    scan_result = NodeScanResult(
                        node_id=self.node.protocol.src_addr,
                        timestamp=time.time(),
                        networks=networks,
                        location_hint=self.location_hint
                    )
                    
                    # Store our own scan
                    self.my_scans.append(scan_result)
                    
                    # Keep only recent scans
                    cutoff = time.time() - 86400
                    self.my_scans = [s for s in self.my_scans if s.timestamp > cutoff]
                    
                    # Broadcast scan to peers
                    await self._broadcast_scan(scan_result)
                    
                    self.logger.info(
                        f"WiFi scan completed",
                        extra={
                            **self.log_extra,
                            'scan_number': scan_count,
                            'network_count': len(networks),
                            'scan_duration': scan_duration,
                            'event_type': 'wifi_scan_complete'
                        }
                    )
                    
                    # Log some network details at debug level
                    for i, net in enumerate(networks[:5]):  # First 5 networks
                        self.logger.debug(
                            f"Network {i+1}: {net.ssid}",
                            extra={
                                **self.log_extra,
                                'bssid': net.bssid,
                                'signal': net.signal_strength,
                                'channel': net.channel
                            }
                        )
                
            except Exception as e:
                self.log_error(e, "WiFi scanning", {'scan_count': scan_count})
            
            # Wait for next scan
            await asyncio.sleep(self.scan_interval)
    
    async def _scan_wifi(self) -> List[WiFiNetwork]:
        """Scan WiFi networks using nmcli"""
        try:
            # Run nmcli command
            cmd = [
                'nmcli', '-t', '-f', 
                'SSID,BSSID,SIGNAL,FREQ,CHAN,SECURITY',
                'dev', 'wifi'
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                self.logger.error(
                    f"nmcli scan failed",
                    extra={
                        **self.log_extra,
                        'return_code': process.returncode,
                        'stderr': stderr.decode()
                    }
                )
                return []
            
            # Parse output
            networks = []
            lines = stdout.decode().strip().split('\n')
            
            for line in lines:
                if not line.strip():
                    continue
                
                parts = line.split(':')
                if len(parts) >= 6:
                    ssid = parts[0] if parts[0] else f"Hidden_{parts[1][:8]}"
                    bssid = parts[1]
                    signal = int(parts[2]) if parts[2].lstrip('-').isdigit() else -100
                    freq = int(parts[3]) if parts[3].isdigit() else 0
                    channel = int(parts[4]) if parts[4].isdigit() else 0
                    security = ':'.join(parts[5:]) if len(parts) > 5 else ''
                    
                    network = WiFiNetwork(
                        ssid=ssid,
                        bssid=bssid,
                        signal_strength=signal,
                        frequency=freq,
                        channel=channel,
                        security=security,
                        timestamp=time.time()
                    )
                    networks.append(network)
            
            return networks
            
        except Exception as e:
            self.log_error(e, "scanning WiFi with nmcli")
            return []
    
    async def _broadcast_scan(self, scan_result: NodeScanResult):
        """Broadcast our WiFi scan to other nodes"""
        payload = {
            'timestamp': scan_result.timestamp,
            'location_hint': scan_result.location_hint,
            'networks': [asdict(net) for net in scan_result.networks]
        }
        
        self.node.send_message('wifi_scan', payload)
        
        self.log_message_sent('wifi_scan', payload, 'broadcast', {
            'network_count': len(scan_result.networks)
        })
    
    async def _analysis_loop(self):
        """Periodically analyze geometry based on collected data"""
        analysis_count = 0
        
        while self.is_active:
            try:
                # Wait a bit for data to accumulate
                await asyncio.sleep(60)
                
                analysis_count += 1
                start_time = time.time()
                
                # Perform geometry analysis
                geometry = await self._analyze_geometry()
                analysis_duration = time.time() - start_time
                
                if geometry and geometry.confidence > 0.3:  # Only update if confident enough
                    old_confidence = self.last_geometry.confidence if self.last_geometry else 0
                    self.last_geometry = geometry
                    
                    # Log geometry update
                    self.logger.info(
                        f"Geometry estimate updated",
                        extra={
                            **self.log_extra,
                            'analysis_number': analysis_count,
                            'confidence': geometry.confidence,
                            'old_confidence': old_confidence,
                            'cluster_count': len(geometry.clusters),
                            'node_count': len(set().union(*geometry.clusters)) if geometry.clusters else 0,
                            'analysis_duration': analysis_duration,
                            'event_type': 'geometry_updated'
                        }
                    )
                    
                    # Log detailed geometry info
                    self.log_network_event(
                        'geometry_analysis',
                        f"Updated network geometry: {len(geometry.clusters)} clusters, confidence {geometry.confidence:.2f}",
                        {
                            'clusters': [[n[:8] + "..." for n in cluster] for cluster in geometry.clusters],
                            'pair_count': len(geometry.node_pairs),
                            'confidence': geometry.confidence
                        }
                    )
                    
                    # Notify callbacks
                    for callback in self.geometry_callbacks:
                        try:
                            callback(geometry)
                        except Exception as e:
                            self.log_error(e, "geometry callback")
                    
                    self.log_performance("geometry_analysis", analysis_duration, {
                        'confidence': geometry.confidence,
                        'cluster_count': len(geometry.clusters)
                    })
                
            except Exception as e:
                self.log_error(e, "geometry analysis", {'analysis_count': analysis_count})
            
            # Analyze every 5 minutes
            await asyncio.sleep(300)
    
    async def _analyze_geometry(self) -> Optional[GeometryEstimate]:
        """Analyze WiFi scan data to estimate node geometry"""
        try:
            # Collect all nodes that have scan data
            all_nodes = set([self.node.protocol.src_addr])
            all_nodes.update(self.peer_scans.keys())
            
            if len(all_nodes) < 2:
                return None  # Need at least 2 nodes
            
            # Get latest scan for each node
            latest_scans = {}
            
            # Add our latest scan
            if self.my_scans:
                latest_scans[self.node.protocol.src_addr] = self.my_scans[-1]
            
            # Add peer latest scans
            for node_id, scans in self.peer_scans.items():
                if scans:
                    latest_scans[node_id] = scans[-1]
            
            if len(latest_scans) < 2:
                return None
            
            # Calculate pairwise similarities
            node_pairs = {}
            distances = {}
            
            nodes = list(latest_scans.keys())
            for i, node1 in enumerate(nodes):
                for j, node2 in enumerate(nodes[i+1:], i+1):
                    similarity = self._calculate_similarity(
                        latest_scans[node1], 
                        latest_scans[node2]
                    )
                    distance = self._estimate_distance(
                        latest_scans[node1],
                        latest_scans[node2]
                    )
                    
                    node_pairs[(node1, node2)] = similarity
                    distances[(node1, node2)] = distance
            
            # Cluster nodes based on similarity
            clusters = self._cluster_nodes(node_pairs, threshold=0.5)
            
            # Calculate overall confidence
            confidence = self._calculate_confidence(node_pairs, latest_scans)
            
            return GeometryEstimate(
                node_pairs=node_pairs,
                clusters=clusters,
                distances=distances,
                confidence=confidence
            )
            
        except Exception as e:
            self.log_error(e, "analyzing geometry")
            return None
    
    def _calculate_similarity(self, scan1: NodeScanResult, scan2: NodeScanResult) -> float:
        """Calculate similarity between two WiFi scans"""
        # Get BSSIDs from both scans
        bssids1 = {net.bssid for net in scan1.networks}
        bssids2 = {net.bssid for net in scan2.networks}
        
        # Calculate Jaccard similarity (intersection over union)
        intersection = len(bssids1.intersection(bssids2))
        union = len(bssids1.union(bssids2))
        
        if union == 0:
            return 0.0
        
        jaccard = intersection / union
        
        # Also consider signal strength similarity for common networks
        signal_similarity = 0.0
        if intersection > 0:
            common_networks = bssids1.intersection(bssids2)
            
            # Build signal strength maps
            signals1 = {net.bssid: net.signal_strength for net in scan1.networks}
            signals2 = {net.bssid: net.signal_strength for net in scan2.networks}
            
            signal_diffs = []
            for bssid in common_networks:
                if bssid in signals1 and bssid in signals2:
                    diff = abs(signals1[bssid] - signals2[bssid])
                    signal_diffs.append(diff)
            
            if signal_diffs:
                avg_diff = sum(signal_diffs) / len(signal_diffs)
                # Convert to similarity (smaller diff = higher similarity)
                signal_similarity = max(0, 1 - (avg_diff / 50))  # 50 dBm max diff
        
        # Combine Jaccard and signal similarity
        return (jaccard * 0.7) + (signal_similarity * 0.3)
    
    def _estimate_distance(self, scan1: NodeScanResult, scan2: NodeScanResult) -> float:
        """Estimate relative distance between nodes based on signal differences"""
        # Find common networks
        bssids1 = {net.bssid for net in scan1.networks}
        bssids2 = {net.bssid for net in scan2.networks}
        common = bssids1.intersection(bssids2)
        
        if not common:
            return float('inf')  # No common networks = very far apart
        
        # Build signal strength maps
        signals1 = {net.bssid: net.signal_strength for net in scan1.networks}
        signals2 = {net.bssid: net.signal_strength for net in scan2.networks}
        
        # Calculate average signal difference for common networks
        signal_diffs = []
        for bssid in common:
            if bssid in signals1 and bssid in signals2:
                diff = abs(signals1[bssid] - signals2[bssid])
                signal_diffs.append(diff)
        
        if not signal_diffs:
            return float('inf')
        
        avg_diff = sum(signal_diffs) / len(signal_diffs)
        
        # Convert signal difference to relative distance estimate
        # This is very rough - real RSSI-to-distance conversion is complex
        # Rule of thumb: ~6dB difference per doubling of distance
        if avg_diff < 3:
            return 1.0  # Very close
        elif avg_diff < 10:
            return 2.0  # Close
        elif avg_diff < 20:
            return 5.0  # Medium distance
        else:
            return 10.0  # Far apart
    
    def _cluster_nodes(self, similarities: Dict[Tuple[str, str], float], threshold: float = 0.5) -> List[List[str]]:
        """Cluster nodes based on similarity threshold"""
        # Simple clustering: nodes with similarity > threshold are in same cluster
        nodes = set()
        for pair in similarities.keys():
            nodes.update(pair)
        
        clusters = []
        remaining = set(nodes)
        
        while remaining:
            # Start new cluster with first remaining node
            seed = remaining.pop()
            cluster = [seed]
            
            # Find all nodes similar to this cluster
            changed = True
            while changed:
                changed = False
                to_add = []
                
                for node in remaining:
                    # Check if node is similar to any node in current cluster
                    for cluster_node in cluster:
                        pair = tuple(sorted([node, cluster_node]))
                        if pair in similarities and similarities[pair] > threshold:
                            to_add.append(node)
                            changed = True
                            break
                
                # Add similar nodes to cluster
                for node in to_add:
                    if node in remaining:
                        remaining.remove(node)
                        cluster.append(node)
            
            clusters.append(cluster)
        
        return clusters
    
    def _calculate_confidence(self, similarities: Dict[Tuple[str, str], float], scans: Dict[str, NodeScanResult]) -> float:
        """Calculate overall confidence in geometry estimate"""
        if not similarities or not scans:
            return 0.0
        
        # Factors that increase confidence:
        # 1. More nodes with data
        # 2. More common networks between nodes
        # 3. More recent scan data
        # 4. Higher number of networks per scan
        
        node_count = len(scans)
        avg_similarity = sum(similarities.values()) / len(similarities)
        
        # Check data freshness (last hour is good)
        current_time = time.time()
        fresh_scans = sum(1 for scan in scans.values() 
                         if current_time - scan.timestamp < 3600)
        freshness = fresh_scans / len(scans)
        
        # Check network density
        avg_networks = sum(len(scan.networks) for scan in scans.values()) / len(scans)
        network_factor = min(1.0, avg_networks / 10)  # 10+ networks is good
        
        # Combine factors
        confidence = (
            (min(node_count, 4) / 4) * 0.3 +  # Up to 4 nodes
            avg_similarity * 0.4 +
            freshness * 0.2 +
            network_factor * 0.1
        )
        
        return min(1.0, confidence)
    
    def add_geometry_callback(self, callback: callable):
        """Add callback for geometry updates"""
        self.geometry_callbacks.append(callback)
    
    def get_current_geometry(self) -> Optional[GeometryEstimate]:
        """Get the current geometry estimate"""
        return self.last_geometry
    
    def get_scan_summary(self) -> Dict:
        """Get summary of scan data"""
        total_scans = len(self.my_scans) + sum(len(scans) for scans in self.peer_scans.values())
        peer_count = len(self.peer_scans)
        network_count = len(self.all_networks)
        
        return {
            'total_scans': total_scans,
            'peer_count': peer_count,
            'unique_networks': network_count,
            'my_scans': len(self.my_scans),
            'last_scan': self.my_scans[-1].timestamp if self.my_scans else None
        }