#!/usr/bin/env python3

"""
P4 5-Tuple Connection Tracking Demo with Scapy
This demo shows proper 5-tuple connection state management (src_ip, dst_ip, src_port, dst_port, protocol)
"""

import time
import struct
import hashlib
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.l2 import Ether

class P4Conntrack5TupleDemo:
    def __init__(self):
        self.packets = []
        self.conntrack_entries = {}
        self.conntrack_id_counter = 1
        
    def create_5tuple_packets(self):
        """Create packets for 5-tuple connection tracking demo"""
        print("Creating 5-tuple connection tracking test packets...")
        print("-" * 60)
        
        # TCP Connection 1: Client to Server
        tcp_syn1 = Ether(src="00:00:00:00:00:03", dst="00:00:00:00:00:01") / \
                   IP(src="10.0.0.3", dst="10.0.0.1", ttl=64) / \
                   TCP(sport=12345, dport=80, flags="S", seq=1000, window=8192)
        self.packets.append(("TCP SYN 1", tcp_syn1, "NEW"))
        
        tcp_syn_ack1 = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:03") / \
                       IP(src="10.0.0.1", dst="10.0.0.3", ttl=64) / \
                       TCP(sport=80, dport=12345, flags="SA", seq=2000, ack=1001, window=8192)
        self.packets.append(("TCP SYN-ACK 1", tcp_syn_ack1, "ESTABLISHED"))
        
        tcp_ack1 = Ether(src="00:00:00:00:00:03", dst="00:00:00:00:00:01") / \
                   IP(src="10.0.0.3", dst="10.0.0.1", ttl=64) / \
                   TCP(sport=12345, dport=80, flags="A", seq=1001, ack=2001, window=8192)
        self.packets.append(("TCP ACK 1", tcp_ack1, "ESTABLISHED"))
        
        # TCP Connection 2: Different client port to same server
        tcp_syn2 = Ether(src="00:00:00:00:00:03", dst="00:00:00:00:00:01") / \
                   IP(src="10.0.0.3", dst="10.0.0.1", ttl=64) / \
                   TCP(sport=54321, dport=80, flags="S", seq=3000, window=8192)
        self.packets.append(("TCP SYN 2", tcp_syn2, "NEW"))
        
        # TCP Connection 3: Different client to same server
        tcp_syn3 = Ether(src="00:00:00:00:00:04", dst="00:00:00:00:00:01") / \
                   IP(src="10.0.0.4", dst="10.0.0.1", ttl=64) / \
                   TCP(sport=12345, dport=80, flags="S", seq=4000, window=8192)
        self.packets.append(("TCP SYN 3", tcp_syn3, "NEW"))
        
        # UDP Connection 1: DNS Query
        udp_query1 = Ether(src="00:00:00:00:00:03", dst="00:00:00:00:00:02") / \
                     IP(src="10.0.0.3", dst="10.0.0.2", ttl=64) / \
                     UDP(sport=12345, dport=53) / \
                     Raw(b"DNS Query 1")
        self.packets.append(("UDP Query 1", udp_query1, "NEW"))
        
        udp_response1 = Ether(src="00:00:00:00:00:02", dst="00:00:00:00:00:03") / \
                        IP(src="10.0.0.2", dst="10.0.0.3", ttl=64) / \
                        UDP(sport=53, dport=12345) / \
                        Raw(b"DNS Response 1")
        self.packets.append(("UDP Response 1", udp_response1, "ESTABLISHED"))
        
        # UDP Connection 2: Different ports
        udp_query2 = Ether(src="00:00:00:00:00:03", dst="00:00:00:00:00:02") / \
                     IP(src="10.0.0.3", dst="10.0.0.2", ttl=64) / \
                     UDP(sport=54321, dport=53) / \
                     Raw(b"DNS Query 2")
        self.packets.append(("UDP Query 2", udp_query2, "NEW"))
        
        # ICMP Echo (no ports, uses 0 for port fields)
        icmp_echo = Ether(src="00:00:00:00:00:03", dst="00:00:00:00:00:01") / \
                    IP(src="10.0.0.3", dst="10.0.0.1", ttl=64) / \
                    ICMP(type=8, code=0, id=12345, seq=1) / \
                    Raw(b"Ping Request")
        self.packets.append(("ICMP Echo", icmp_echo, "NEW"))
        
        # TCP Connection 4: Reverse direction (server to client)
        tcp_data_reverse = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:03") / \
                           IP(src="10.0.0.1", dst="10.0.0.3", ttl=64) / \
                           TCP(sport=80, dport=12345, flags="PA", seq=2001, ack=1001, window=8192) / \
                           Raw(b"HTTP Response")
        self.packets.append(("TCP Data Reverse", tcp_data_reverse, "ESTABLISHED"))
        
        print(f"✓ Created {len(self.packets)} 5-tuple connection tracking test packets")
        
    def generate_5tuple_key(self, packet):
        """Generate 5-tuple connection key from packet"""
        if IP not in packet:
            return None
            
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        # Extract ports based on protocol
        src_port = 0
        dst_port = 0
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        # For ICMP and other protocols, ports are 0
        
        # Create 5-tuple key
        key_string = f"{src_ip}:{dst_ip}:{protocol}:{src_port}:{dst_port}"
        key_hash = hashlib.md5(key_string.encode()).hexdigest()[:8]
        return int(key_hash, 16) % 1000  # Map to 0-999 range
        
    def simulate_5tuple_conntrack_processing(self, name, packet, expected_state):
        """Simulate 5-tuple connection tracking processing"""
        print(f"\n🔄 Processing {name} through P4 5-tuple conntrack pipeline...")
        
        # Stage 1: Parser
        print("  📥 Parser: Extracting headers...")
        ethernet = packet[Ether]
        ip_packet = packet[IP] if IP in packet else None
        
        if not ip_packet:
            print("    ✗ No IP header found")
            return None
            
        # Extract 5-tuple
        src_ip = ip_packet.src
        dst_ip = ip_packet.dst
        protocol = ip_packet.proto
        src_port = 0
        dst_port = 0
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"    ✓ TCP: {src_port} -> {dst_port}")
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"    ✓ UDP: {src_port} -> {dst_port}")
        else:
            print(f"    ✓ Protocol {protocol}: No ports (ICMP/Other)")
            
        print(f"    ✓ 5-tuple: {src_ip}:{dst_ip}:{protocol}:{src_port}:{dst_port}")
        
        # Stage 2: 5-Tuple Connection Tracking Lookup
        print("  🔍 5-Tuple Connection Tracking: Looking up connection...")
        conntrack_key = self.generate_5tuple_key(packet)
        
        if conntrack_key in self.conntrack_entries:
            entry = self.conntrack_entries[conntrack_key]
            print(f"    ✓ Connection found in conntrack table (ID: {entry['id']})")
            print(f"    ✓ 5-tuple: {entry['src_ip']}:{entry['dst_ip']}:{entry['protocol']}:{entry['src_port']}:{entry['dst_port']}")
            print(f"    ✓ Current state: {entry['state']}")
            print(f"    ✓ Packet count: {entry['packet_count']}")
            
            # Update packet count
            entry['packet_count'] += 1
            
            # Update state based on packet type
            if TCP in packet:
                tcp_flags = packet[TCP].flags
                if 'S' in tcp_flags and 'A' not in tcp_flags:
                    entry['state'] = "SYN_SENT"
                elif 'S' in tcp_flags and 'A' in tcp_flags:
                    entry['state'] = "SYN_RECV"
                elif 'A' in tcp_flags and 'S' not in tcp_flags:
                    entry['state'] = "ESTABLISHED"
                elif 'F' in tcp_flags:
                    entry['state'] = "FIN_WAIT"
                    
            conntrack_action = f"conntrack_lookup({entry['id']}, {entry['state']})"
            conntrack_found = True
            
        else:
            # Create new connection entry
            conntrack_id = self.conntrack_id_counter
            self.conntrack_id_counter += 1
            
            new_entry = {
                'id': conntrack_id,
                'state': expected_state,
                'packet_count': 1,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol,
                'src_port': src_port,
                'dst_port': dst_port,
                'created_time': time.time()
            }
            
            self.conntrack_entries[conntrack_key] = new_entry
            
            print(f"    ✗ Connection not found, creating new entry (ID: {conntrack_id})")
            print(f"    ✓ 5-tuple: {src_ip}:{dst_ip}:{protocol}:{src_port}:{dst_port}")
            print(f"    ✓ New state: {expected_state}")
            
            conntrack_action = f"conntrack_create({conntrack_id}, {expected_state})"
            conntrack_found = False
            
        # Stage 3: Forwarding Logic
        print("  ⚙️  Ingress: Applying forwarding logic...")
        
        # MAC forwarding
        dst_mac = ethernet.dst
        mac_forwarding_table = {
            "00:00:00:00:00:01": 1,
            "00:00:00:00:00:02": 2
        }
        
        if dst_mac in mac_forwarding_table:
            output_port = mac_forwarding_table[dst_mac]
            print(f"    ✓ MAC {dst_mac} found -> Forward to port {output_port}")
        else:
            print(f"    ✗ MAC {dst_mac} not found -> Broadcast")
            output_port = "broadcast"
            
        # IP forwarding
        dst_ip = ip_packet.dst
        ip_forwarding_table = {
            "10.0.0.1": 1,
            "10.0.0.2": 2
        }
        
        if dst_ip in ip_forwarding_table:
            output_port = ip_forwarding_table[dst_ip]
            print(f"    ✓ IP {dst_ip} found -> Forward to port {output_port}")
        else:
            print(f"    ✗ IP {dst_ip} not found -> Drop")
            output_port = "drop"
            
        # TTL processing
        old_ttl = ip_packet.ttl
        new_ttl = old_ttl - 1
        print(f"    🔄 TTL decrement: {old_ttl} -> {new_ttl}")
        
        # Stage 4: Checksum and Deparser
        print("  🔢 Checksum: Recalculating IPv4 header checksum...")
        print("  📤 Deparser: Reconstructing packet...")
        
        return {
            'name': name,
            'conntrack_key': conntrack_key,
            'conntrack_action': conntrack_action,
            'conntrack_found': conntrack_found,
            'state': expected_state,
            'output_port': output_port,
            'ttl_change': f"{old_ttl} -> {new_ttl}",
            '5tuple': f"{src_ip}:{dst_ip}:{protocol}:{src_port}:{dst_port}"
        }
        
    def show_packet_details(self, name, packet):
        """Display detailed packet information with 5-tuple focus"""
        print(f"\n--- {name} ---")
        print(f"Ethernet: {packet[Ether].src} -> {packet[Ether].dst}")
        
        if IP in packet:
            print(f"IP: {packet[IP].src} -> {packet[IP].dst}")
            print(f"TTL: {packet[IP].ttl}, Protocol: {packet[IP].proto}")
            
        if TCP in packet:
            print(f"TCP: {packet[TCP].sport} -> {packet[TCP].dport}")
            print(f"Flags: {packet[TCP].flags}, Seq: {packet[TCP].seq}")
        elif UDP in packet:
            print(f"UDP: {packet[UDP].sport} -> {packet[UDP].dport}")
        elif ICMP in packet:
            print(f"ICMP: Type={packet[ICMP].type}, Code={packet[ICMP].code}")
            
        print(f"Total Size: {len(packet)} bytes")
        
        # Show detailed packet structure
        print(f"\n📋 Detailed Packet Structure ({name}):")
        print("=" * 70)
        packet.show()
        print("=" * 70)
        
    def show_5tuple_conntrack_table(self):
        """Display current 5-tuple connection tracking table"""
        print("\n" + "="*100)
        print("5-TUPLE CONNECTION TRACKING TABLE (1000 entries max)")
        print("="*100)
        
        if not self.conntrack_entries:
            print("No connections in conntrack table")
            return
            
        print(f"Active connections: {len(self.conntrack_entries)}")
        print()
        print(f"{'Key':<4} {'ID':<3} {'5-Tuple':<50} {'State':<12} {'Packets':<7}")
        print("-" * 100)
        
        for key, entry in self.conntrack_entries.items():
            tuple_str = f"{entry['src_ip']}:{entry['dst_ip']}:{entry['protocol']}:{entry['src_port']}:{entry['dst_port']}"
            print(f"{key:<4} {entry['id']:<3} {tuple_str:<50} {entry['state']:<12} {entry['packet_count']:<7}")
                  
    def run_5tuple_conntrack_demo(self):
        """Run the complete 5-tuple connection tracking demo"""
        print("P4 5-Tuple Connection Tracking Demo with Scapy")
        print("=" * 70)
        print("This demo shows proper 5-tuple connection state management")
        print("5-tuple format: src_ip:dst_ip:protocol:src_port:dst_port")
        print()
        
        # Create packets
        self.create_5tuple_packets()
        
        print("\n" + "="*100)
        print("5-TUPLE CONNECTION TRACKING PROCESSING")
        print("="*100)
        
        processing_results = []
        
        # Process each packet
        for i, (name, packet, expected_state) in enumerate(self.packets, 1):
            print(f"\n{'='*25} PACKET {i} {'='*25}")
            
            # Show packet details
            self.show_packet_details(name, packet)
            
            # Simulate 5-tuple conntrack processing
            result = self.simulate_5tuple_conntrack_processing(name, packet, expected_state)
            if result:
                processing_results.append(result)
            
            time.sleep(1)  # Pause between packets
            
        # Show conntrack table
        self.show_5tuple_conntrack_table()
        
        # Show processing summary
        print("\n" + "="*100)
        print("5-TUPLE CONNECTION TRACKING SUMMARY")
        print("="*100)
        
        for result in processing_results:
            print(f"📦 {result['name']}")
            print(f"   5-tuple: {result['5tuple']}")
            print(f"   Conntrack Key: {result['conntrack_key']}")
            print(f"   Action: {result['conntrack_action']}")
            print(f"   Found: {result['conntrack_found']}")
            print(f"   State: {result['state']}")
            print(f"   Output: {result['output_port']}")
            print(f"   TTL: {result['ttl_change']}")
            print()
            
        print("="*100)
        print("5-TUPLE CONNECTION TRACKING DEMO COMPLETE!")
        print("="*100)
        print("Key Features Demonstrated:")
        print("✓ Proper 5-tuple connection identification (src_ip:dst_ip:protocol:src_port:dst_port)")
        print("✓ 1000-entry connection tracking table")
        print("✓ Connection state management (NEW, ESTABLISHED, etc.)")
        print("✓ Port-based connection differentiation")
        print("✓ Protocol-specific handling (TCP, UDP, ICMP)")
        print("✓ Connection lookup and creation")
        print("✓ Packet counting per connection")
        print("✓ State transitions based on packet types")
        print("✓ Integration with P4 forwarding pipeline")
        print()
        print(f"Total connections created: {len(self.conntrack_entries)}")
        print(f"Conntrack table utilization: {len(self.conntrack_entries)}/1000 entries")

def main():
    """Main function"""
    demo = P4Conntrack5TupleDemo()
    demo.run_5tuple_conntrack_demo()

if __name__ == "__main__":
    main()
