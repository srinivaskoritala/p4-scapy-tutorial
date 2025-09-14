#!/usr/bin/env python3

"""
Simple P4 Demo with Scapy Packet Generation
This version creates packets and shows how they would be processed by P4
"""

import time
import struct
from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether

class SimpleP4ScapyDemo:
    def __init__(self):
        self.packets = []
        self.processing_results = []
        
    def create_demo_packets(self):
        """Create various test packets using Scapy"""
        print("Creating demo packets with Scapy...")
        print("-" * 40)
        
        # Packet 1: Known MAC destination
        pkt1 = Ether(src="00:00:00:00:00:03", dst="00:00:00:00:00:01") / \
               IP(src="10.0.0.3", dst="10.0.0.1", ttl=64) / \
               ICMP(type=8, code=0) / Raw(b"Hello P4 World!")
        self.packets.append(("Known MAC", pkt1))
        
        # Packet 2: Unknown MAC destination (should broadcast)
        pkt2 = Ether(src="00:00:00:00:00:03", dst="00:00:00:00:00:99") / \
               IP(src="10.0.0.3", dst="10.0.0.99", ttl=64) / \
               ICMP(type=8, code=0) / Raw(b"Unknown MAC test")
        self.packets.append(("Unknown MAC", pkt2))
        
        # Packet 3: Known IP destination
        pkt3 = Ether(src="00:00:00:00:00:03", dst="00:00:00:00:00:02") / \
               IP(src="10.0.0.3", dst="10.0.0.2", ttl=64) / \
               ICMP(type=8, code=0) / Raw(b"Known IP test")
        self.packets.append(("Known IP", pkt3))
        
        # Packet 4: TCP-like packet
        pkt4 = Ether(src="00:00:00:00:00:03", dst="00:00:00:00:00:01") / \
               IP(src="10.0.0.3", dst="10.0.0.1", ttl=64) / \
               Raw(b"TCP-like payload for P4 processing")
        self.packets.append(("TCP-like", pkt4))
        
        print(f"✓ Created {len(self.packets)} test packets")
        
    def show_packet_details(self, name, packet):
        """Display detailed packet information"""
        print(f"\n--- {name} ---")
        print(f"Ethernet: {packet[Ether].src} -> {packet[Ether].dst}")
        
        if IP in packet:
            print(f"IP: {packet[IP].src} -> {packet[IP].dst}")
            print(f"TTL: {packet[IP].ttl}")
            print(f"Protocol: {packet[IP].proto}")
            
        if ICMP in packet:
            print(f"ICMP: Type={packet[ICMP].type}, Code={packet[ICMP].code}")
            
        if Raw in packet:
            print(f"Payload: {bytes(packet[Raw])}")
            
        print(f"Total Size: {len(packet)} bytes")
        
        # Show detailed packet structure with pkt.show()
        print(f"\n📋 Detailed Packet Structure ({name}):")
        print("=" * 50)
        packet.show()
        print("=" * 50)
        
    def simulate_p4_processing(self, name, packet):
        """Simulate P4 packet processing pipeline"""
        print(f"\n🔄 Processing {name} through P4 pipeline...")
        
        # Stage 1: Parser
        print("  📥 Parser: Extracting headers...")
        ethernet = packet[Ether]
        ip_packet = packet[IP] if IP in packet else None
        
        # Stage 2: Ingress Processing
        print("  ⚙️  Ingress: Applying forwarding logic...")
        
        # MAC forwarding table lookup
        dst_mac = ethernet.dst
        mac_forwarding_table = {
            "00:00:00:00:00:01": 1,
            "00:00:00:00:00:02": 2
        }
        
        if dst_mac in mac_forwarding_table:
            output_port = mac_forwarding_table[dst_mac]
            print(f"    ✓ MAC {dst_mac} found -> Forward to port {output_port}")
            mac_action = f"forward(port={output_port})"
        else:
            print(f"    ✗ MAC {dst_mac} not found -> Broadcast")
            mac_action = "broadcast()"
            
        # IP forwarding table lookup
        if ip_packet:
            dst_ip = ip_packet.dst
            ip_forwarding_table = {
                "10.0.0.1": 1,
                "10.0.0.2": 2
            }
            
            if dst_ip in ip_forwarding_table:
                output_port = ip_forwarding_table[dst_ip]
                print(f"    ✓ IP {dst_ip} found -> Forward to port {output_port}")
                ip_action = f"forward(port={output_port})"
            else:
                print(f"    ✗ IP {dst_ip} not found -> Drop")
                ip_action = "drop()"
        else:
            ip_action = "N/A (no IP header)"
            
        # TTL processing
        if ip_packet:
            old_ttl = ip_packet.ttl
            new_ttl = old_ttl - 1
            print(f"    🔄 TTL decrement: {old_ttl} -> {new_ttl}")
            
        # Stage 3: Checksum computation
        if ip_packet:
            print("  🔢 Checksum: Recalculating IPv4 header checksum...")
            
        # Stage 4: Deparser
        print("  📤 Deparser: Reconstructing packet...")
        
        # Store processing result
        result = {
            "name": name,
            "src_mac": ethernet.src,
            "dst_mac": ethernet.dst,
            "src_ip": ip_packet.src if ip_packet else "N/A",
            "dst_ip": ip_packet.dst if ip_packet else "N/A",
            "old_ttl": ip_packet.ttl if ip_packet else "N/A",
            "new_ttl": (ip_packet.ttl - 1) if ip_packet else "N/A",
            "mac_action": mac_action,
            "ip_action": ip_action,
            "output_port": output_port if dst_mac in mac_forwarding_table else "broadcast"
        }
        
        self.processing_results.append(result)
        return result
        
    def show_processing_summary(self):
        """Show summary of all packet processing"""
        print("\n" + "="*80)
        print("P4 PROCESSING SUMMARY")
        print("="*80)
        
        for result in self.processing_results:
            print(f"\n📦 {result['name']}")
            print(f"   Ethernet: {result['src_mac']} -> {result['dst_mac']}")
            print(f"   IP: {result['src_ip']} -> {result['dst_ip']}")
            print(f"   TTL: {result['old_ttl']} -> {result['new_ttl']}")
            print(f"   MAC Action: {result['mac_action']}")
            print(f"   IP Action: {result['ip_action']}")
            print(f"   Output: Port {result['output_port']}")
            
    def show_packet_hex_dump(self, packet):
        """Show hex dump of packet"""
        print("\n📋 Packet Hex Dump:")
        hexdump(packet)
        
    def run_demo(self):
        """Run the complete demo"""
        print("P4 Scapy Packet Processing Demo")
        print("=" * 50)
        print("This demo shows how packets would be processed by our P4 program")
        print()
        
        # Create packets
        self.create_demo_packets()
        
        print("\n" + "="*80)
        print("PACKET GENERATION AND PROCESSING")
        print("="*80)
        
        # Process each packet
        for i, (name, packet) in enumerate(self.packets, 1):
            print(f"\n{'='*20} PACKET {i} {'='*20}")
            
            # Show packet details
            self.show_packet_details(name, packet)
            
            # Simulate P4 processing
            result = self.simulate_p4_processing(name, packet)
            
            # Show hex dump for first packet
            if i == 1:
                self.show_packet_hex_dump(packet)
            
            time.sleep(1)  # Pause between packets
            
        # Show summary
        self.show_processing_summary()
        
        print("\n" + "="*80)
        print("DEMO COMPLETE!")
        print("="*80)
        print("Key P4 Concepts Demonstrated:")
        print("✓ Packet parsing and header extraction")
        print("✓ Table lookups for forwarding decisions")
        print("✓ Action execution (forward, broadcast, drop)")
        print("✓ Packet modification (TTL decrement)")
        print("✓ Checksum recalculation")
        print("✓ Packet reconstruction and output")
        print()
        print("This is exactly what happens in a real P4 switch!")

def main():
    """Main function"""
    demo = SimpleP4ScapyDemo()
    demo.run_demo()

if __name__ == "__main__":
    main()
