# Copyright (C) 2026 Musa Jaradat
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# orin/collectors/triggered_pcap.py
"""
orin.collectors.triggered_pcap – Triggered PCAP Ring-Buffer Capture
==================================================================
Captures actual network payloads only when specific triggers occur
(YARA rule match, IOC hit, or security event). Uses a ring-buffer
to maintain recent packet history without consuming excessive disk space.

Features
--------
- Circular ring-buffer for pre-trigger packet capture
- Post-trigger continued capture for full context
- Integration with YARA engine and IOC matcher
- Automatic PCAP file generation with timestamps
- Configurable buffer size and capture duration
- Filter-based capture (by IP, port, process)

Public API
----------
TriggeredPcapCapture        – Main class for managing triggered captures
start_capture()             – Begin monitoring for triggers
stop_capture()              – Stop capture and save buffered packets
on_trigger()                – Called when a YARA/IOC trigger fires
get_captured_pcaps()        – Retrieve list of captured PCAP files
"""
import time
import os
import socket
import struct
import threading
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from collections import deque
from datetime import datetime

try:
    from scapy.all import (
        sniff, wrpcap, rdpcap, IP, TCP, UDP, ICMP,
        Ether
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    # Fallback stubs if scapy not available
    sniff = None
    wrpcap = None
    rdpcap = None
    IP = None
    TCP = None
    UDP = None
    ICMP = None
    Ether = None

logger = logging.getLogger(__name__)


class PacketBuffer:
    """Circular buffer for storing raw packets with timestamps.

    Maintains a fixed-size buffer of recent packets. When the buffer
    fills, oldest packets are discarded (FIFO). Each packet entry
    includes the raw packet data, timestamp, and metadata.

    Attributes
    ----------
    max_packets : int
        Maximum number of packets to retain in buffer
    max_memory_mb : float
        Maximum memory usage in MB before dropping packets
    """

    def __init__(self, max_packets: int = 10000, max_memory_mb: float = 100.0):
        """Initialize packet buffer.

        Parameters
        ----------
        max_packets : int
            Maximum packet count in ring buffer (default: 10000)
        max_memory_mb : float
            Maximum memory usage in megabytes (default: 100.0)
        """
        self.max_packets = max_packets
        self.max_memory_bytes = int(max_memory_mb * 1024 * 1024)
        self.buffer: deque = deque(maxlen=max_packets)
        self.current_memory = 0
        self._lock = threading.Lock()
        self.total_packets_seen = 0
        self.dropped_packets = 0

    def add_packet(self, packet_data: bytes, timestamp: float,
                   metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Add a packet to the buffer.

        Parameters
        ----------
        packet_data : bytes
            Raw packet bytes
        timestamp : float
            Unix timestamp of packet capture
        metadata : dict, optional
            Additional metadata (src_ip, dst_ip, ports, etc.)

        Returns
        -------
        bool
            True if packet was added, False if dropped due to memory limits
        """
        with self._lock:
            packet_size = len(packet_data)

            # Check memory limit
            if self.current_memory + packet_size > self.max_memory_bytes:
                # Drop oldest packets until we have space
                while self.buffer and self.current_memory + packet_size > self.max_memory_bytes:
                    old_packet = self.buffer.popleft()
                    self.current_memory -= len(old_packet['data'])
                    self.dropped_packets += 1

                # If still no space, drop this packet
                if self.current_memory + packet_size > self.max_memory_bytes:
                    self.dropped_packets += 1
                    return False

            # Add packet
            packet_entry = {
                'data': packet_data,
                'timestamp': timestamp,
                'metadata': metadata or {},
                'size': packet_size
            }
            self.buffer.append(packet_entry)
            self.current_memory += packet_size
            self.total_packets_seen += 1
            return True

    def get_packets(self, start_time: Optional[float] = None,
                    end_time: Optional[float] = None,
                    src_ip: Optional[str] = None,
                    dst_ip: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve packets from buffer with optional filters.

        Parameters
        ----------
        start_time : float, optional
            Only return packets after this timestamp
        end_time : float, optional
            Only return packets before this timestamp
        src_ip : str, optional
            Filter by source IP address
        dst_ip : str, optional
            Filter by destination IP address

        Returns
        -------
        list
            List of packet dictionaries matching filters
        """
        with self._lock:
            results = []
            for packet in self.buffer:
                # Time filters
                if start_time and packet['timestamp'] < start_time:
                    continue
                if end_time and packet['timestamp'] > end_time:
                    continue

                # IP filters
                metadata = packet.get('metadata', {})
                if src_ip and metadata.get('src_ip') != src_ip:
                    continue
                if dst_ip and metadata.get('dst_ip') != dst_ip:
                    continue

                results.append(packet)

            return results

    def clear(self) -> None:
        """Clear all packets from buffer."""
        with self._lock:
            self.buffer.clear()
            self.current_memory = 0

    def stats(self) -> Dict[str, Any]:
        """Get buffer statistics.

        Returns
        -------
        dict
            Buffer statistics including packet count, memory usage, drops
        """
        with self._lock:
            return {
                'current_packets': len(self.buffer),
                'max_packets': self.max_packets,
                'memory_bytes': self.current_memory,
                'memory_mb': self.current_memory / (1024 * 1024),
                'total_packets_seen': self.total_packets_seen,
                'dropped_packets': self.dropped_packets,
                'drop_rate': self.dropped_packets / max(1, self.total_packets_seen)
            }


class TriggeredPcapCapture:
    """Triggered PCAP capture manager with ring-buffer support.

    Continuously monitors network traffic in a ring-buffer. When a
    trigger event occurs (YARA match, IOC hit, security alert), the
    buffered packets are saved to a PCAP file along with continued
    post-trigger capture.

    Parameters
    ----------
    capture_dir : str
        Directory to store captured PCAP files
    pre_trigger_seconds : float
        How many seconds of pre-trigger traffic to retain (default: 30.0)
    post_trigger_seconds : float
        How many seconds to continue capturing after trigger (default: 60.0)
    max_buffer_mb : float
        Maximum memory for ring buffer in MB (default: 50.0)
    interface : str, optional
        Network interface to capture on (None = all interfaces)
    bpf_filter : str, optional
        BPF filter string for packet capture
    """

    def __init__(self, capture_dir: str = "/tmp/orin_pcaps",
                 pre_trigger_seconds: float = 30.0,
                 post_trigger_seconds: float = 60.0,
                 max_buffer_mb: float = 50.0,
                 interface: Optional[str] = None,
                 bpf_filter: Optional[str] = None):
        """Initialize triggered PCAP capture.

        Parameters
        ----------
        capture_dir : str
            Directory for storing PCAP files
        pre_trigger_seconds : float
            Seconds of pre-trigger buffer to retain
        post_trigger_seconds : float
            Seconds to capture after trigger
        max_buffer_mb : float
            Maximum ring buffer size in MB
        interface : str, optional
            Network interface name (e.g., 'eth0')
        bpf_filter : str, optional
            BPF capture filter (e.g., 'port 80 or port 443')
        """
        self.capture_dir = Path(capture_dir)
        self.capture_dir.mkdir(parents=True, exist_ok=True)

        self.pre_trigger_seconds = pre_trigger_seconds
        self.post_trigger_seconds = post_trigger_seconds
        self.max_buffer_mb = max_buffer_mb
        self.interface = interface
        self.bpf_filter = bpf_filter

        # Ring buffer for continuous capture
        self.packet_buffer = PacketBuffer(
            max_packets=50000,
            max_memory_mb=max_buffer_mb
        )

        # Capture state
        self._capture_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._is_capturing = False
        self._active_triggers: Dict[str, Dict[str, Any]] = {}
        self._captured_files: List[Dict[str, Any]] = []
        self._lock = threading.RLock()

        # Statistics
        self.triggers_fired = 0
        self.files_written = 0
        self.total_packets_captured = 0

    def start_capture(self) -> bool:
        """Start background packet capture thread.

        Begins continuous monitoring of network traffic. Packets are
        stored in the ring-buffer until a trigger event occurs.

        Returns
        -------
        bool
            True if capture started successfully
        """
        if self._is_capturing:
            logger.warning("Capture already running")
            return False

        is_root = False
        try:
            is_root = (os.geteuid() == 0)
        except AttributeError:
            pass

        if not SCAPY_AVAILABLE or not is_root:
            logger.warning("Scapy not available or not running as root - using simulated capture mode")
            self._is_capturing = True
            self._capture_thread = threading.Thread(target=self._simulate_capture_loop)
            self._capture_thread.daemon = True
            self._capture_thread.start()
            return True

        self._stop_event.clear()
        self._is_capturing = True

        self._capture_thread = threading.Thread(target=self._capture_loop)
        self._capture_thread.daemon = True
        self._capture_thread.start()

        logger.info(f"Started triggered PCAP capture (buffer: {self.max_buffer_mb}MB)")
        return True

    def stop_capture(self) -> List[str]:
        """Stop capture and return list of saved PCAP files.

        Returns
        -------
        list
            Paths to all captured PCAP files
        """
        self._stop_event.set()
        self._is_capturing = False

        if self._capture_thread:
            self._capture_thread.join(timeout=5.0)

        # Save any remaining buffered packets
        if self.packet_buffer.buffer:
            self._save_buffer_to_pcap("shutdown_capture")

        logger.info(f"Stopped capture. Files written: {self.files_written}")
        return [f['filepath'] for f in self._captured_files]

    def on_trigger(self, trigger_id: str, trigger_type: str,
                   trigger_details: Dict[str, Any],
                   target_ips: Optional[Set[str]] = None,
                   target_ports: Optional[Set[int]] = None) -> str:
        """Handle a trigger event (YARA match, IOC hit, etc.).

        When called, saves pre-trigger buffered packets and continues
        capturing post-trigger traffic for the configured duration.

        Parameters
        ----------
        trigger_id : str
            Unique identifier for this trigger event
        trigger_type : str
            Type of trigger ('yara', 'ioc', 'alert', etc.)
        trigger_details : dict
            Details about what triggered the capture
        target_ips : set, optional
            Specific IPs to focus capture on
        target_ports : set, optional
            Specific ports to focus capture on

        Returns
        -------
        str
            Path to the saved PCAP file
        """
        with self._lock:
            self.triggers_fired += 1
            timestamp = time.time()
            trigger_time = datetime.fromtimestamp(timestamp)

            logger.info(f"Trigger fired: {trigger_type} - {trigger_id}")

            # Calculate time window
            pre_trigger_start = timestamp - self.pre_trigger_seconds

            # Get relevant packets from buffer
            packets = self.packet_buffer.get_packets(
                start_time=pre_trigger_start
            )

            # Filter by target IPs/ports if specified
            if target_ips or target_ports:
                filtered_packets = []
                for pkt in packets:
                    meta = pkt.get('metadata', {})
                    src_ip = meta.get('src_ip')
                    dst_ip = meta.get('dst_ip')
                    src_port = meta.get('src_port')
                    dst_port = meta.get('dst_port')

                    ip_match = not target_ips or src_ip in target_ips or dst_ip in target_ips
                    port_match = not target_ports or src_port in target_ports or dst_port in target_ports

                    if ip_match or port_match:
                        filtered_packets.append(pkt)

                packets = filtered_packets

            # Generate filename
            filename = f"trigger_{trigger_id}_{trigger_time.strftime('%Y%m%d_%H%M%S')}.pcap"
            filepath = self.capture_dir / filename

            # Start post-trigger capture period
            post_trigger_end = timestamp + self.post_trigger_seconds

            # Save packets to PCAP
            pcap_path = self._save_packets_to_file(
                packets, filepath, trigger_id, trigger_type,
                trigger_details, timestamp, post_trigger_end
            )

            # Track active trigger for continued capture
            self._active_triggers[trigger_id] = {
                'trigger_type': trigger_type,
                'trigger_details': trigger_details,
                'start_time': timestamp,
                'end_time': post_trigger_end,
                'target_ips': target_ips,
                'target_ports': target_ports,
                'filepath': str(pcap_path),
                'packets_saved': len(packets)
            }

            return str(pcap_path)

    def _capture_loop(self) -> None:
        """Main capture loop using scapy."""
        def packet_handler(packet):
            """Process each captured packet."""
            if self._stop_event.is_set():
                return

            try:
                # Extract packet metadata
                timestamp = time.time()
                metadata = {}

                if IP in packet:
                    metadata['src_ip'] = packet[IP].src
                    metadata['dst_ip'] = packet[IP].dst
                    metadata['protocol'] = 'IP'

                    if TCP in packet:
                        metadata['src_port'] = packet[TCP].sport
                        metadata['dst_port'] = packet[TCP].dport
                        metadata['protocol'] = 'TCP'
                        metadata['flags'] = str(packet[TCP].flags)
                    elif UDP in packet:
                        metadata['src_port'] = packet[UDP].sport
                        metadata['dst_port'] = packet[UDP].dport
                        metadata['protocol'] = 'UDP'
                    elif ICMP in packet:
                        metadata['protocol'] = 'ICMP'

                # Convert packet to bytes and add to buffer
                packet_bytes = bytes(packet)
                self.packet_buffer.add_packet(
                    packet_bytes, timestamp, metadata
                )
                self.total_packets_captured += 1

                # Check for active triggers that need continued capture
                self._process_active_triggers(timestamp, packet, metadata)

            except Exception as e:
                logger.error(f"Error processing packet: {e}")

        # Start scapy sniff
        try:
            sniff(
                iface=self.interface,
                prn=packet_handler,
                filter=self.bpf_filter,
                store=False,
                stop_filter=lambda x: self._stop_event.is_set()
            )
        except Exception as e:
            logger.error(f"Capture error: {e}")
            self._is_capturing = False

    def _simulate_capture_loop(self) -> None:
        """Simulated capture loop when scapy unavailable.

        In simulation mode, we monitor /proc/net/tcp and /proc/net/udp
        to track active connections and generate synthetic packet records.
        """
        while not self._stop_event.is_set():
            try:
                # Read active connections
                connections = self._read_proc_net_connections()
                timestamp = time.time()

                for conn in connections:
                    # Create synthetic packet record
                    metadata = {
                        'src_ip': conn.get('local_ip'),
                        'dst_ip': conn.get('remote_ip'),
                        'src_port': conn.get('local_port'),
                        'dst_port': conn.get('remote_port'),
                        'protocol': conn.get('protocol', 'TCP')
                    }

                    # Synthetic packet header (minimal)
                    packet_bytes = self._create_synthetic_packet(metadata)
                    self.packet_buffer.add_packet(packet_bytes, timestamp, metadata)
                    self.total_packets_captured += 1

                # Check active triggers
                self._process_active_triggers_simulation(timestamp, connections)

            except Exception as e:
                logger.error(f"Simulation error: {e}")

            time.sleep(1.0)  # Sample every second

    def _read_proc_net_connections(self) -> List[Dict[str, Any]]:
        """Read connection info from /proc/net."""
        connections = []

        for proto in ['tcp', 'udp']:
            try:
                path = Path(f"/proc/net/{proto}")
                if not path.exists():
                    continue

                with open(path, 'r') as f:
                    lines = f.readlines()[1:]  # Skip header

                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 10:
                            # Parse local and remote addresses
                            local = parts[1].split(':')
                            remote = parts[2].split(':')

                            if len(local) == 2 and len(remote) == 2:
                                local_ip = socket.inet_ntoa(struct.pack('>I', int(local[0], 16)))
                                local_port = int(local[1], 16)
                                remote_ip = socket.inet_ntoa(struct.pack('>I', int(remote[0], 16)))
                                remote_port = int(remote[1], 16)

                                connections.append({
                                    'protocol': proto.upper(),
                                    'local_ip': local_ip,
                                    'local_port': local_port,
                                    'remote_ip': remote_ip,
                                    'remote_port': remote_port,
                                    'state': parts[3] if proto == 'tcp' else 'ESTABLISHED'
                                })
            except Exception as e:
                logger.debug(f"Error reading /proc/net/{proto}: {e}")

        return connections

    def _create_synthetic_packet(self, metadata: Dict[str, Any]) -> bytes:
        """Create minimal synthetic packet for simulation mode."""
        # Simple fake packet header
        src_ip = metadata.get('src_ip', '0.0.0.0')
        dst_ip = metadata.get('dst_ip', '0.0.0.0')
        src_port = metadata.get('src_port', 0)
        dst_port = metadata.get('dst_port', 0)

        # Minimal IP + TCP header simulation
        packet = bytearray()
        packet.extend(src_ip.encode())
        packet.extend(dst_ip.encode())
        packet.extend(struct.pack('>H', src_port))
        packet.extend(struct.pack('>H', dst_port))
        packet.extend(struct.pack('>I', int(time.time())))

        return bytes(packet)

    def _process_active_triggers(self, timestamp: float, packet,
                                  metadata: Dict[str, Any]) -> None:
        """Process packets for active post-trigger captures."""
        completed_triggers = []

        for trigger_id, trigger_info in list(self._active_triggers.items()):
            if timestamp > trigger_info['end_time']:
                completed_triggers.append(trigger_id)
                continue

            # Check if packet matches trigger targets
            target_ips = trigger_info.get('target_ips')
            target_ports = trigger_info.get('target_ports')

            should_capture = True
            if target_ips:
                src_ip = metadata.get('src_ip')
                dst_ip = metadata.get('dst_ip')
                should_capture = src_ip in target_ips or dst_ip in target_ips

            if should_capture and target_ports:
                src_port = metadata.get('src_port')
                dst_port = metadata.get('dst_port')
                should_capture = src_port in target_ports or dst_port in target_ports

            if should_capture:
                # Append to existing PCAP
                try:
                    filepath = Path(trigger_info['filepath'])

                    # Read existing, append new, write back
                    if filepath.exists():
                        existing = rdpcap(str(filepath))
                        existing.append(packet)
                        wrpcap(str(filepath), existing)
                        trigger_info['packets_saved'] = len(existing)
                except Exception as e:
                    logger.error(f"Error appending to PCAP: {e}")

        # Remove completed triggers
        for trigger_id in completed_triggers:
            del self._active_triggers[trigger_id]

    def _process_active_triggers_simulation(self, timestamp: float,
                                            connections: List[Dict[str, Any]]) -> None:
        """Process connections for active triggers in simulation mode."""
        completed_triggers = []

        for trigger_id, trigger_info in list(self._active_triggers.items()):
            if timestamp > trigger_info['end_time']:
                completed_triggers.append(trigger_id)
                continue

            # In simulation, just track that we're still capturing
            trigger_info['last_activity'] = timestamp

        for trigger_id in completed_triggers:
            logger.info(f"Post-trigger capture complete: {trigger_id}")
            del self._active_triggers[trigger_id]

    def _save_packets_to_file(self, packets: List[Dict[str, Any]],
                              filepath: Path, trigger_id: str,
                              trigger_type: str, trigger_details: Dict[str, Any],
                              trigger_time: float, post_trigger_end: float) -> Path:
        """Save packets to PCAP file with metadata."""
        if not packets:
            # Create empty PCAP with metadata
            logger.warning(f"No packets to save for trigger {trigger_id}")
            filepath = filepath.with_suffix('.pcap.empty')
            filepath.touch()
        elif SCAPY_AVAILABLE:
            try:
                # Convert packet dicts to scapy packets
                scapy_packets = []
                for pkt in packets:
                    try:
                        # Reconstruct packet from bytes
                        raw_data = pkt['data']
                        scapy_pkt = Ether(raw_data)
                        scapy_packets.append(scapy_pkt)
                    except Exception:
                        continue

                if scapy_packets:
                    wrpcap(str(filepath), scapy_packets)
                else:
                    filepath = filepath.with_suffix('.pcap.empty')
                    filepath.touch()
            except Exception as e:
                logger.error(f"Error writing PCAP: {e}")
                filepath = filepath.with_suffix('.pcap.error')
                filepath.touch()
        else:
            # Write raw packet data
            try:
                with open(filepath, 'wb') as f:
                    # Simple PCAP global header
                    magic_number = 0xa1b2c3d4
                    version_major = 2
                    version_minor = 4
                    thiszone = 0
                    sigfigs = 0
                    snaplen = 65535
                    network = 1  # LINKTYPE_ETHERNET

                    f.write(struct.pack('<I', magic_number))
                    f.write(struct.pack('<H', version_major))
                    f.write(struct.pack('<H', version_minor))
                    f.write(struct.pack('<i', thiszone))
                    f.write(struct.pack('<I', sigfigs))
                    f.write(struct.pack('<I', snaplen))
                    f.write(struct.pack('<I', network))

                    # Write packets
                    for pkt in packets:
                        ts_sec = int(pkt['timestamp'])
                        ts_usec = int((pkt['timestamp'] - ts_sec) * 1000000)
                        incl_len = len(pkt['data'])
                        orig_len = len(pkt['data'])

                        f.write(struct.pack('<I', ts_sec))
                        f.write(struct.pack('<I', ts_usec))
                        f.write(struct.pack('<I', incl_len))
                        f.write(struct.pack('<I', orig_len))
                        f.write(pkt['data'])
            except Exception as e:
                logger.error(f"Error writing raw PCAP: {e}")

        # Record capture metadata
        with self._lock:
            self._captured_files.append({
                'filepath': str(filepath),
                'trigger_id': trigger_id,
                'trigger_type': trigger_type,
                'trigger_details': trigger_details,
                'trigger_time': trigger_time,
                'post_trigger_end': post_trigger_end,
                'packets_count': len(packets),
                'created_at': datetime.now().isoformat()
            })
            self.files_written += 1

        logger.info(f"Saved PCAP: {filepath} ({len(packets)} packets)")
        return filepath

    def _save_buffer_to_pcap(self, prefix: str = "capture") -> Optional[str]:
        """Save entire current buffer to PCAP file.

        Parameters
        ----------
        prefix : str
            Filename prefix

        Returns
        -------
        str, optional
            Path to saved file, or None if failed
        """
        packets = self.packet_buffer.get_packets()
        if not packets:
            return None

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{prefix}_{timestamp}.pcap"
        filepath = self.capture_dir / filename

        self._save_packets_to_file(
            packets, filepath, f"manual_{prefix}", "manual",
            {}, time.time(), time.time()
        )

        return str(filepath)

    def get_captured_pcaps(self) -> List[Dict[str, Any]]:
        """Get list of all captured PCAP files with metadata.

        Returns
        -------
        list
            List of capture metadata dictionaries
        """
        with self._lock:
            return list(self._captured_files)

    def get_stats(self) -> Dict[str, Any]:
        """Get capture statistics.

        Returns
        -------
        dict
            Comprehensive capture statistics
        """
        return {
            'is_capturing': self._is_capturing,
            'triggers_fired': self.triggers_fired,
            'files_written': self.files_written,
            'total_packets_captured': self.total_packets_captured,
            'active_triggers': len(self._active_triggers),
            'buffer_stats': self.packet_buffer.stats(),
            'capture_dir': str(self.capture_dir),
            'config': {
                'pre_trigger_seconds': self.pre_trigger_seconds,
                'post_trigger_seconds': self.post_trigger_seconds,
                'max_buffer_mb': self.max_buffer_mb,
                'interface': self.interface,
                'bpf_filter': self.bpf_filter
            }
        }


def create_pcap_from_connections(connections: List[Dict[str, Any]],
                                 output_path: str) -> str:
    """Create a PCAP file from connection records.

    Utility function to generate PCAP files from collected connection
    data for forensic analysis or evidence export.

    Parameters
    ----------
    connections : list
        List of connection dictionaries with IP/port information
    output_path : str
        Path for output PCAP file

    Returns
    -------
    str
        Path to created PCAP file
    """
    if not SCAPY_AVAILABLE:
        logger.warning("Scapy not available, cannot create PCAP")
        return ""

    try:
        packets = []
        for conn in connections:
            # Create synthetic packet for each connection
            src_ip = conn.get('local_ip', '0.0.0.0')
            dst_ip = conn.get('remote_ip', '0.0.0.0')
            src_port = conn.get('local_port', 0)
            dst_port = conn.get('remote_port', 0)

            if conn.get('protocol', '').upper() == 'UDP':
                pkt = Ether()/IP(src=src_ip, dst=dst_ip)/UDP(sport=src_port, dport=dst_port)
            else:
                pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port)

            packets.append(pkt)

        if packets:
            wrpcap(output_path, packets)
            logger.info(f"Created PCAP with {len(packets)} packets: {output_path}")
            return output_path
        else:
            logger.warning("No packets to write")
            return ""

    except Exception as e:
        logger.error(f"Error creating PCAP: {e}")
        return ""


# Convenience functions for integration with analysis engine
def on_yara_match(match_details: Dict[str, Any],
                  pcap_capture: Optional[TriggeredPcapCapture] = None,
                  target_ips: Optional[Set[str]] = None) -> Optional[str]:
    """Handler for YARA rule matches to trigger PCAP capture.

    Parameters
    ----------
    match_details : dict
        YARA match information (rule name, file, strings, etc.)
    pcap_capture : TriggeredPcapCapture, optional
        Active PCAP capture instance
    target_ips : set, optional
        IPs to focus capture on

    Returns
    -------
    str, optional
        Path to triggered PCAP file
    """
    if not pcap_capture:
        return None

    trigger_id = f"yara_{match_details.get('rule', 'unknown')}_{int(time.time())}"

    return pcap_capture.on_trigger(
        trigger_id=trigger_id,
        trigger_type='yara',
        trigger_details=match_details,
        target_ips=target_ips
    )


def on_ioc_hit(ioc_details: Dict[str, Any],
               pcap_capture: Optional[TriggeredPcapCapture] = None,
               matched_ips: Optional[Set[str]] = None) -> Optional[str]:
    """Handler for IOC matches to trigger PCAP capture.

    Parameters
    ----------
    ioc_details : dict
        IOC match information (type, value, source, etc.)
    pcap_capture : TriggeredPcapCapture, optional
        Active PCAP capture instance
    matched_ips : set, optional
        Matched IP addresses

    Returns
    -------
    str, optional
        Path to triggered PCAP file
    """
    if not pcap_capture:
        return None

    trigger_id = f"ioc_{ioc_details.get('type', 'unknown')}_{int(time.time())}"

    return pcap_capture.on_trigger(
        trigger_id=trigger_id,
        trigger_type='ioc',
        trigger_details=ioc_details,
        target_ips=matched_ips
    )