# Copyright (C) 2026 Musa Jaradat
# Licensed under GNU AGPLv3
import os
import sys
import time
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch, MagicMock, mock_open

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from orin.collectors.triggered_pcap import (
    PacketBuffer,
    TriggeredPcapCapture,
    create_pcap_from_connections,
    on_yara_match,
    on_ioc_hit
)

class TestTriggeredPcap(unittest.TestCase):

    def test_packet_buffer_basic(self):
        buffer = PacketBuffer(max_packets=100, max_memory_mb=10.0)

        # Test adding packets
        for i in range(10):
            packet_data = b"test_packet_" + bytes([i])
            timestamp = time.time()
            metadata = {'src_ip': '192.168.1.1', 'dst_ip': '10.0.0.1'}

            result = buffer.add_packet(packet_data, timestamp, metadata)
            self.assertTrue(result)

        stats = buffer.stats()
        self.assertEqual(stats['current_packets'], 10)
        self.assertEqual(stats['total_packets_seen'], 10)
        self.assertEqual(stats['dropped_packets'], 0)

        # Test retrieving packets
        packets = buffer.get_packets()
        self.assertEqual(len(packets), 10)

        # Test filtering by IP
        filtered = buffer.get_packets(src_ip='192.168.1.1')
        self.assertEqual(len(filtered), 10)

        filtered = buffer.get_packets(dst_ip='10.0.0.1')
        self.assertEqual(len(filtered), 10)

        filtered = buffer.get_packets(src_ip='192.168.1.999')
        self.assertEqual(len(filtered), 0)

        # Test clear
        buffer.clear()
        stats = buffer.stats()
        self.assertEqual(stats['current_packets'], 0)
        self.assertEqual(stats['memory_bytes'], 0)

    def test_packet_buffer_ring_behavior(self):
        # Small buffer to force overflow
        buffer = PacketBuffer(max_packets=5, max_memory_mb=0.001)

        # Add more packets than buffer size
        for i in range(20):
            packet_data = b"x" * 100  # 100 bytes each
            buffer.add_packet(packet_data, time.time())

        stats = buffer.stats()
        self.assertTrue(stats['current_packets'] <= 5)
        self.assertTrue(stats['dropped_packets'] > 0)
        self.assertEqual(stats['total_packets_seen'], 20)

        # Test adding packet larger than max memory
        large_buffer = PacketBuffer(max_packets=5, max_memory_mb=0.0001) # ~104 bytes
        large_packet = b"x" * 200
        result = large_buffer.add_packet(large_packet, time.time())
        self.assertFalse(result)

    def test_triggered_pcap_initialization(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            capture = TriggeredPcapCapture(
                capture_dir=tmpdir,
                pre_trigger_seconds=10.0,
                post_trigger_seconds=20.0,
                max_buffer_mb=25.0
            )

            self.assertEqual(capture.capture_dir, Path(tmpdir))
            self.assertEqual(capture.pre_trigger_seconds, 10.0)
            self.assertEqual(capture.post_trigger_seconds, 20.0)
            self.assertEqual(capture.max_buffer_mb, 25.0)

            stats = capture.get_stats()
            self.assertFalse(stats['is_capturing'])
            self.assertEqual(stats['triggers_fired'], 0)

    def test_triggered_pcap_start_stop(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            capture = TriggeredPcapCapture(capture_dir=tmpdir)

            # Start capture
            result = capture.start_capture()
            self.assertTrue(result)

            # Start again should warn/fail
            result2 = capture.start_capture()
            self.assertFalse(result2)

            time.sleep(0.5)

            stats = capture.get_stats()
            self.assertTrue(stats['is_capturing'])

            # Stop capture
            files = capture.stop_capture()
            time.sleep(0.5)
            stats = capture.get_stats()
            self.assertFalse(stats['is_capturing'])

    @patch("orin.collectors.triggered_pcap.SCAPY_AVAILABLE", True)
    @patch("orin.collectors.triggered_pcap.wrpcap")
    @patch("orin.collectors.triggered_pcap.rdpcap")
    @patch("orin.collectors.triggered_pcap.Ether")
    def test_trigger_event(self, mock_ether, mock_rdpcap, mock_wrpcap):
        with tempfile.TemporaryDirectory() as tmpdir:
            capture = TriggeredPcapCapture(
                capture_dir=tmpdir,
                pre_trigger_seconds=5.0,
                post_trigger_seconds=2.0
            )

            capture.start_capture()
            time.sleep(0.5)

            base_time = time.time()
            for i in range(5):
                packet_data = b"test_packet_" + bytes([i]) * 20
                metadata = {'src_ip': '192.168.1.100', 'dst_ip': '10.0.0.50'}
                capture.packet_buffer.add_packet(packet_data, base_time + i * 0.1, metadata)

            time.sleep(0.2)

            trigger_details = {
                'rule': 'Test_Malware_Rule',
                'file': '/tmp/suspicious.exe',
                'match_string': 'malicious_pattern'
            }

            pcap_file = capture.on_trigger(
                trigger_id='test_trigger_001',
                trigger_type='yara',
                trigger_details=trigger_details,
                target_ips={'192.168.1.100', '10.0.0.50'}
            )

            self.assertIsNotNone(pcap_file)
            stats = capture.get_stats()
            self.assertEqual(stats['triggers_fired'], 1)

            capture.stop_capture()

    def test_multiple_triggers(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            capture = TriggeredPcapCapture(capture_dir=tmpdir)
            capture.start_capture()
            time.sleep(0.5)

            base_time = time.time()
            for i in range(10):
                packet_data = b"multi_test_" + bytes([i]) * 10
                metadata = {'src_ip': f'192.168.1.{i % 3}', 'dst_ip': '10.0.0.1'}
                capture.packet_buffer.add_packet(packet_data, base_time + i * 0.1, metadata)

            for i in range(3):
                trigger_details = {'rule': f'Rule_{i}', 'severity': 'high'}
                pcap_file = capture.on_trigger(
                    trigger_id=f'multi_trigger_{i}',
                    trigger_type='ioc',
                    trigger_details=trigger_details,
                    target_ips={f'192.168.1.{i}'}
                )
                self.assertIsNotNone(pcap_file)

            stats = capture.get_stats()
            self.assertEqual(stats['triggers_fired'], 3)
            capture.stop_capture()

    @patch("orin.collectors.triggered_pcap.SCAPY_AVAILABLE", True)
    @patch("orin.collectors.triggered_pcap.wrpcap")
    @patch("orin.collectors.triggered_pcap.Ether")
    @patch("orin.collectors.triggered_pcap.IP")
    @patch("orin.collectors.triggered_pcap.TCP")
    @patch("orin.collectors.triggered_pcap.UDP")
    def test_create_pcap_from_connections(self, mock_udp, mock_tcp, mock_ip, mock_ether, mock_wrpcap):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, 'connections.pcap')

            connections = [
                {
                    'local_ip': '192.168.1.10',
                    'local_port': 45678,
                    'remote_ip': '10.0.0.1',
                    'remote_port': 80,
                    'protocol': 'TCP'
                },
                {
                    'local_ip': '192.168.1.10',
                    'local_port': 53000,
                    'remote_ip': '8.8.8.8',
                    'remote_port': 53,
                    'protocol': 'UDP'
                }
            ]

            result_path = create_pcap_from_connections(connections, output_path)
            self.assertEqual(result_path, output_path)

            # Test empty connections
            result_empty = create_pcap_from_connections([], output_path)
            self.assertEqual(result_empty, "")

    @patch("orin.collectors.triggered_pcap.SCAPY_AVAILABLE", False)
    def test_scapy_not_available_fallback(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, 'fallback.pcap')
            connections = [{'local_ip': '1.1.1.1', 'remote_ip': '2.2.2.2'}]

            # create_pcap_from_connections should return empty string if no scapy
            result = create_pcap_from_connections(connections, output_path)
            self.assertEqual(result, "")

            # TriggeredPcapCapture should save raw PCAP header and packets manually
            capture = TriggeredPcapCapture(capture_dir=tmpdir)
            capture.start_capture()
            capture.packet_buffer.add_packet(b"raw_ethernet_data", time.time())
            pcap_file = capture.on_trigger("test_raw", "manual", {})
            self.assertTrue(os.path.exists(pcap_file))
            capture.stop_capture()

    def test_convenience_functions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            capture = TriggeredPcapCapture(capture_dir=tmpdir)
            capture.start_capture()
            time.sleep(0.5)

            # Add packets to buffer
            base_time = time.time()
            for i in range(3):
                packet_data = b"conv_test_" + bytes([i]) * 15
                metadata = {'src_ip': '185.220.101.1', 'dst_ip': '192.168.1.1'}
                capture.packet_buffer.add_packet(packet_data, base_time + i * 0.1, metadata)

            # Test on_yara_match
            yara_match = {
                'rule': 'CryptoMiner_Generic',
                'file': '/tmp/miner',
                'strings': ['stratum+tcp', 'wallet_address']
            }
            res_yara = on_yara_match(yara_match, capture, target_ips={'pool.mining.com'})
            self.assertIsNotNone(res_yara)

            # Test on_ioc_hit
            ioc_match = {
                'type': 'ip',
                'value': '185.220.101.1',
                'source': 'threat_feed',
                'confidence': 0.95
            }
            res_ioc = on_ioc_hit(ioc_match, capture, matched_ips={'185.220.101.1'})
            self.assertIsNotNone(res_ioc)

            # Test None capture returns None
            self.assertIsNone(on_yara_match(yara_match, None))
            self.assertIsNone(on_ioc_hit(ioc_match, None))

            capture.stop_capture()

    def test_buffer_time_filtering(self):
        buffer = PacketBuffer(max_packets=1000)
        base_time = time.time()

        # Add packets 1 second apart
        for i in range(10):
            packet_data = b"packet_" + bytes([i])
            buffer.add_packet(packet_data, base_time + i)

        # Filter by time range
        start_time = base_time + 3
        end_time = base_time + 7
        filtered = buffer.get_packets(start_time=start_time, end_time=end_time)
        self.assertEqual(len(filtered), 5)

    def test_statistics_accuracy(self):
        buffer = PacketBuffer(max_packets=100, max_memory_mb=1.0)
        packet_size = 100
        num_packets = 50

        for i in range(num_packets):
            buffer.add_packet(b"x" * packet_size, time.time())

        stats = buffer.stats()
        self.assertEqual(stats['current_packets'], num_packets)
        self.assertEqual(stats['total_packets_seen'], num_packets)
        self.assertEqual(stats['memory_bytes'], num_packets * packet_size)

    @patch("orin.collectors.triggered_pcap.os.geteuid")
    def test_start_capture_geteuid_exception(self, mock_geteuid):
        mock_geteuid.side_effect = AttributeError("No geteuid")
        with tempfile.TemporaryDirectory() as tmpdir:
            capture = TriggeredPcapCapture(capture_dir=tmpdir)
            result = capture.start_capture()
            self.assertTrue(result)
            capture.stop_capture()

    @patch("orin.collectors.triggered_pcap.Path.exists", return_value=False)
    def test_read_proc_net_connections_missing(self, mock_exists):
        with tempfile.TemporaryDirectory() as tmpdir:
            capture = TriggeredPcapCapture(capture_dir=tmpdir)
            conns = capture._read_proc_net_connections()
            self.assertEqual(len(conns), 0)

    def test_read_proc_net_connections_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            capture = TriggeredPcapCapture(capture_dir=tmpdir)
            with patch("builtins.open", side_effect=OSError("Read error")):
                conns = capture._read_proc_net_connections()
            self.assertEqual(len(conns), 0)

    @patch("orin.collectors.triggered_pcap.SCAPY_AVAILABLE", True)
    @patch("orin.collectors.triggered_pcap.sniff")
    @patch("orin.collectors.triggered_pcap.rdpcap")
    @patch("orin.collectors.triggered_pcap.wrpcap")
    def test_capture_loop_and_active_triggers(self, mock_wrpcap, mock_rdpcap, mock_sniff):
        import orin.collectors.triggered_pcap as tp
        orig_IP = getattr(tp, 'IP', None)
        orig_TCP = getattr(tp, 'TCP', None)
        orig_UDP = getattr(tp, 'UDP', None)
        orig_ICMP = getattr(tp, 'ICMP', None)
        orig_Ether = getattr(tp, 'Ether', None)
        
        tp.IP = 'IP_mock'
        tp.TCP = 'TCP_mock'
        tp.UDP = 'UDP_mock'
        tp.ICMP = 'ICMP_mock'
        tp.Ether = 'Ether_mock'

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                capture = TriggeredPcapCapture(capture_dir=tmpdir)
                capture._is_capturing = True
                
                # Setup active trigger for target IPs and target ports
                capture._active_triggers['t1'] = {
                    'trigger_type': 'yara',
                    'trigger_details': {},
                    'start_time': time.time(),
                    'end_time': time.time() + 10,
                    'target_ips': {'192.168.1.1'},
                    'target_ports': {80},
                    'filepath': os.path.join(tmpdir, "active.pcap"),
                    'packets_saved': 0
                }
                # Setup an expired trigger
                capture._active_triggers['t_exp'] = {
                    'trigger_type': 'ioc',
                    'trigger_details': {},
                    'start_time': time.time() - 20,
                    'end_time': time.time() - 10,
                    'target_ips': None,
                    'target_ports': None,
                    'filepath': os.path.join(tmpdir, "exp.pcap"),
                    'packets_saved': 0
                }

                # Setup fake rdpcap list
                mock_rdpcap.return_value = []

                class MockPacket:
                    def __init__(self, layers, src, dst, sport=None, dport=None, flags=None):
                        self.layers = layers
                        self.src = src
                        self.dst = dst
                        self.sport = sport
                        self.dport = dport
                        self.flags = flags

                    def __contains__(self, layer):
                        return layer in self.layers

                    def __getitem__(self, layer):
                        m = MagicMock()
                        if layer == 'IP_mock':
                            m.src = self.src
                            m.dst = self.dst
                        elif layer == 'TCP_mock':
                            m.sport = self.sport
                            m.dport = self.dport
                            m.flags = self.flags
                        elif layer == 'UDP_mock':
                            m.sport = self.sport
                            m.dport = self.dport
                        return m

                    def __bytes__(self):
                        return b"fake packet bytes"

                # Mock sniff to invoke packet_handler
                def sniff_side_effect(iface=None, prn=None, filter=None, store=False, stop_filter=None):
                    # 1. TCP packet matching target
                    pkt_tcp = MockPacket(
                        layers=['IP_mock', 'TCP_mock'],
                        src="192.168.1.1",
                        dst="10.0.0.1",
                        sport=1234,
                        dport=80,
                        flags="S"
                    )
                    prn(pkt_tcp)

                    # 2. UDP packet not matching target
                    pkt_udp = MockPacket(
                        layers=['IP_mock', 'UDP_mock'],
                        src="192.168.1.99",
                        dst="10.0.0.99",
                        sport=1234,
                        dport=53
                    )
                    prn(pkt_udp)

                    # 3. Exception packet
                    pkt_err = MagicMock()
                    pkt_err.__contains__.side_effect = Exception("Sniff packet error")
                    prn(pkt_err)

                mock_sniff.side_effect = sniff_side_effect

                # Call capture loop directly
                capture._capture_loop()

                # check if expired trigger was removed
                self.assertNotIn('t_exp', capture._active_triggers)
                self.assertIn('t1', capture._active_triggers)
        finally:
            tp.IP = orig_IP
            tp.TCP = orig_TCP
            tp.UDP = orig_UDP
            tp.ICMP = orig_ICMP
            tp.Ether = orig_Ether

    @patch("orin.collectors.triggered_pcap.time.sleep")
    def test_simulate_capture_loop(self, mock_sleep):
        with tempfile.TemporaryDirectory() as tmpdir:
            capture = TriggeredPcapCapture(capture_dir=tmpdir)
            capture._is_capturing = True
            
            # Setup active trigger
            capture._active_triggers['t_sim'] = {
                'trigger_type': 'yara',
                'trigger_details': {},
                'start_time': time.time(),
                'end_time': time.time() + 10,
                'target_ips': None,
                'target_ports': None,
                'filepath': os.path.join(tmpdir, "sim.pcap"),
                'packets_saved': 0
            }
            # Expired active trigger
            capture._active_triggers['t_exp'] = {
                'trigger_type': 'ioc',
                'trigger_details': {},
                'start_time': time.time() - 20,
                'end_time': time.time() - 10,
                'filepath': os.path.join(tmpdir, "exp.pcap"),
                'packets_saved': 0
            }

            # Mock read connections to return some data
            capture._read_proc_net_connections = MagicMock(return_value=[
                {'local_ip': '127.0.0.1', 'remote_ip': '8.8.8.8', 'local_port': 4444, 'remote_port': 53, 'protocol': 'UDP'}
            ])

            # Stop loop after first sleep
            mock_sleep.side_effect = lambda x: capture._stop_event.set()

            capture._simulate_capture_loop()

            self.assertNotIn('t_exp', capture._active_triggers)
            self.assertIn('t_sim', capture._active_triggers)

    @patch("orin.collectors.triggered_pcap.SCAPY_AVAILABLE", True)
    @patch("orin.collectors.triggered_pcap.Ether")
    def test_save_packets_to_file_edge_cases(self, mock_ether):
        with tempfile.TemporaryDirectory() as tmpdir:
            capture = TriggeredPcapCapture(capture_dir=tmpdir)
            
            # Empty packets case (lines 648-650)
            pcap_empty = capture.on_trigger(
                trigger_id='empty_trig',
                trigger_type='yara',
                trigger_details={},
                target_ips={'9.9.9.9'} # none match
            )
            self.assertTrue(pcap_empty.endswith('.pcap.empty'))

            # Ether reconstruction exception case (lines 661-662)
            mock_ether.side_effect = Exception("Ether build failed")
            capture.packet_buffer.add_packet(b"raw_data", time.time())
            pcap_err = capture.on_trigger(
                trigger_id='err_trig',
                trigger_type='yara',
                trigger_details={}
            )
            self.assertTrue(pcap_err.endswith('.pcap.empty'))

    def test_save_buffer_to_pcap_empty(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            capture = TriggeredPcapCapture(capture_dir=tmpdir)
            res = capture._save_buffer_to_pcap()
            self.assertIsNone(res)

    @patch("orin.collectors.triggered_pcap.SCAPY_AVAILABLE", True)
    @patch("orin.collectors.triggered_pcap.wrpcap")
    def test_create_pcap_from_connections_error(self, mock_wrpcap):
        mock_wrpcap.side_effect = Exception("Write failed")
        conns = [{'local_ip': '1.1.1.1'}]
        res = create_pcap_from_connections(conns, "error.pcap")
        self.assertEqual(res, "")

if __name__ == '__main__':
    unittest.main()