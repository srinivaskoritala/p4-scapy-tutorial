#!/usr/bin/env python3

"""
P4 Connection Tracking Demo with Scapy
This demo shows connection state management with a 1000-entry conntrack table
"""

import time
import struct
import hashlib
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.l2 import Ether

class P4ConntrackDemo:
    def __init__(self):
        self.packets = []
        self.conntrack_entries = {}
        self.conntrack_id_counter = 1
        
    def create_conntrack_packets(self):
        """Create packets for connection tracking demo"""
        print("Creating connection tracking test packets...")
        print("-" * 50)
        
        # TCP Connection Establishment (SYN, SYN-ACK, ACK)
        tcp_syn = Ether(src="00:00:00:00:00:03", dst="00:00:00:00:00:01") / \
                  IP(src="10.0.0.3", dst="10.0.0.1", ttl=64) / \
                  TCP(sport=12345, dport=80, flags="S", seq=1000, window=8192)
        self.packets.append(("TCP SYN", tcp_syn, "NEW"))
        
        tcp_syn_ack = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:03") / \
                      IP(src="10.0.0.1", dst="10.0.0.3", ttl=64) / \
                      TCP(sport=80, dport=12345, flags="SA", seq=2000, ack=1001, window=8192)
        self.packets.append(("TCP SYN-ACK", tcp_syn_ack, "ESTABLISHED"))
        
        tcp_ack = Ether(src="00:00:00:00:00:03", dst="00:00:00:00:00:01") / \
                  IP(src="10.0.0.3", dst="10.0.0.1", ttl=64) / \
                  TCP(sport=12345, dport=80, flags="A", seq=1001, ack=2001, window=8192)
        self.packets.append(("TCP ACK", tcp_ack, "ESTABLISHED"))
        
        # Data packets in established connection
        tcp_data1 = Ether(src="00:00:00:00:00:03", dst="00:00:00:00:00:01") / \
                    IP(src="10.0.0.3", dst="10.0.0.1", ttl=64) / \
                    TCP(sport=12345, dport=80, flags="PA", seq=1001, ack=2001, window=8192) / \
                    Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        self.packets.append(("TCP Data 1", tcp_data1, "ESTABLISHED"))
        
        tcp_data2 = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:03") / \
                    IP(src="10.0.0.1", dst="10.0.0.3", ttl=64) / \
                    TCP(sport=80, dport=12345, flags="PA", seq=2001, ack=1035, window=8192) / \
                    Raw(b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello World!")
        self.packets.append(("TCP Data 2", tcp_data2, "ESTABLISHED"))
        
        # UDP Connection (stateless but we track it)
        udp_packet1 = Ether(src="00:00:00:00:00:03", dst="00:00:00:00:00:02") / \
                      IP(src="10.0.0.3", dst="10.0.0.2", ttl=64) / \
                      UDP(sport=12345, dport=53) / \
                      Raw(b"DNS Query")
        self.packets.append(("UDP Query", udp_packet1, "NEW"))
        
        udp_packet2 = Ether(src="00:00:00:00:00:02", dst="00:00:00:00:00:03") / \
                      IP(src="10.0.0.2", dst="10.0.0.3", ttl=64) / \
                      UDP(sport=53, dport=12345) / \
                      Raw(b"DNS Response")
        self.packets.append(("UDP Response", udp_packet2, "ESTABLISHED"))
        
        # ICMP Echo (ping)
        icmp_echo = Ether(src="00:00:00:00:00:03", dst="00:00:00:00:00:01") / \
                    IP(src="10.0.0.3", dst="10.0.0.1", ttl=64) / \
                    ICMP(type=8, code=0, id=12345, seq=1) / \
                    Raw(b"Ping Request")
        self.packets.append(("ICMP Echo", icmp_echo, "NEW"))
        
        # Multiple connections to test conntrack table
        for i in range(5):
            src_port = 20000 + i
            tcp_conn = Ether(src="00:00:00:00:00:03", dst="00:00:00:00:00:01") / \
                       IP(src="10.0.0.3", dst="10.0.0.1", ttl=64) / \
                       TCP(sport=src_port, dport=80, flags="S", seq=1000+i*1000, window=8192)
            self.packets.append((f"TCP Conn {i+1}", tcp_conn, "NEW"))
        
        print(f"✓ Created {len(self.packets)} connection tracking test packets")
        
    def generate_conntrack_key(self, packet):
        """Generate connection tracking key from packet"""
        if IP not in packet:
            return None
            
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        # Create a hash-based key for the connection
        key_string = f"{src_ip}:{dst_ip}:{protocol}"
        key_hash = hashlib.md5(key_string.encode()).hexdigest()[:8]
        return int(key_hash, 16) % 1000  # Map to 0-999 range
        
    def simulate_conntrack_processing(self, name, packet, expected_state):
        """Simulate connection tracking processing"""
        print(f"\n🔄 Processing {name} through P4 conntrack pipeline...")
        
        # Stage 1: Parser
        print("  📥 Parser: Extracting headers...")
        ethernet = packet[Ether]
        ip_packet = packet[IP] if IP in packet else None
        
        if not ip_packet:
            print("    ✗ No IP header found")
            return None
            
        # Stage 2: Connection Tracking Lookup
        print("  🔍 Connection Tracking: Looking up connection...")
        conntrack_key = self.generate_conntrack_key(packet)
        
        if conntrack_key in self.conntrack_entries:
            entry = self.conntrack_entries[conntrack_key]
            print(f"    ✓ Connection found in conntrack table (ID: {entry['id']})")
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
                'src_ip': ip_packet.src,
                'dst_ip': ip_packet.dst,
                'protocol': ip_packet.proto,
                'created_time': time.time()
            }
            
            self.conntrack_entries[conntrack_key] = new_entry
            
            print(f"    ✗ Connection not found, creating new entry (ID: {conntrack_id})")
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
            'ttl_change': f"{old_ttl} -> {new_ttl}"
        }
        
    def show_packet_details(self, name, packet):
        """Display detailed packet information with conntrack focus"""
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
        print("=" * 60)
        packet.show()
        print("=" * 60)
        
    def show_conntrack_table(self):
        """Display current connection tracking table"""
        print("\n" + "="*80)
        print("CONNECTION TRACKING TABLE (1000 entries max)")
        print("="*80)
        
        if not self.conntrack_entries:
            print("No connections in conntrack table")
            return
            
        print(f"Active connections: {len(self.conntrack_entries)}")
        print()
        
        for key, entry in self.conntrack_entries.items():
            print(f"Key {key:3d}: ID={entry['id']:3d} | {entry['src_ip']:12s} -> {entry['dst_ip']:12s} | "
                  f"Proto={entry['protocol']:2d} | State={entry['state']:12s} | "
                  f"Packets={entry['packet_count']:3d}")
                  
    def run_conntrack_demo(self):
        """Run the complete connection tracking demo"""
        print("P4 Connection Tracking Demo with Scapy")
        print("=" * 60)
        print("This demo shows connection state management with a 1000-entry conntrack table")
        print()
        
        # Create packets
        self.create_conntrack_packets()
        
        print("\n" + "="*80)
        print("CONNECTION TRACKING PROCESSING")
        print("="*80)
        
        processing_results = []
        
        # Process each packet
        for i, (name, packet, expected_state) in enumerate(self.packets, 1):
            print(f"\n{'='*20} PACKET {i} {'='*20}")
            
            # Show packet details
            self.show_packet_details(name, packet)
            
            # Simulate conntrack processing
            result = self.simulate_conntrack_processing(name, packet, expected_state)
            if result:
                processing_results.append(result)
            
            time.sleep(1)  # Pause between packets
            
        # Show conntrack table
        self.show_conntrack_table()
        
        # Show processing summary
        print("\n" + "="*80)
        print("CONNECTION TRACKING SUMMARY")
        print("="*80)
        
        for result in processing_results:
            print(f"📦 {result['name']}")
            print(f"   Conntrack Key: {result['conntrack_key']}")
            print(f"   Action: {result['conntrack_action']}")
            print(f"   Found: {result['conntrack_found']}")
            print(f"   State: {result['state']}")
            print(f"   Output: {result['output_port']}")
            print(f"   TTL: {result['ttl_change']}")
            print()
            
        print("="*80)
        print("CONNECTION TRACKING DEMO COMPLETE!")
        print("="*80)
        print("Key Features Demonstrated:")
        print("✓ 1000-entry connection tracking table")
        print("✓ Connection state management (NEW, ESTABLISHED, etc.)")
        print("✓ Connection lookup and creation")
        print("✓ Packet counting per connection")
        print("✓ State transitions based on packet types")
        print("✓ Integration with P4 forwarding pipeline")
        print()
        print(f"Total connections created: {len(self.conntrack_entries)}")
        print(f"Conntrack table utilization: {len(self.conntrack_entries)}/1000 entries")

def main():
    """Main function"""
    demo = P4ConntrackDemo()
    demo.run_conntrack_demo()

if __name__ == "__main__":
    main()
