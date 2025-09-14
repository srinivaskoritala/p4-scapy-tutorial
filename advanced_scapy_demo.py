#!/usr/bin/env python3

"""
Advanced P4 Demo with Scapy - Multiple Protocol Support
This demo shows packet crafting and processing for various network protocols
"""

import time
import struct
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dns import DNS, DNSQR

class AdvancedP4ScapyDemo:
    def __init__(self):
        self.packets = []
        self.processing_results = []
        
    def create_protocol_packets(self):
        """Create packets for various network protocols"""
        print("Creating advanced protocol packets with Scapy...")
        print("-" * 50)
        
        # 1. ICMP Echo Request (Ping)
        pkt1 = Ether(src="00:00:00:00:00:03", dst="00:00:00:00:00:01") / \
               IP(src="10.0.0.3", dst="10.0.0.1", ttl=64) / \
               ICMP(type=8, code=0, id=12345, seq=1) / \
               Raw(b"P4 ICMP Test Payload")
        self.packets.append(("ICMP Echo Request", pkt1))
        
        # 2. TCP SYN Packet
        pkt2 = Ether(src="00:00:00:00:00:03", dst="00:00:00:00:00:01") / \
               IP(src="10.0.0.3", dst="10.0.0.1", ttl=64) / \
               TCP(sport=12345, dport=80, flags="S", seq=1000, window=8192)
        self.packets.append(("TCP SYN", pkt2))
        
        # 3. UDP DNS Query
        pkt3 = Ether(src="00:00:00:00:00:03", dst="00:00:00:00:00:02") / \
               IP(src="10.0.0.3", dst="10.0.0.2", ttl=64) / \
               UDP(sport=12345, dport=53) / \
               DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))
        self.packets.append(("UDP DNS Query", pkt3))
        
        # 4. ARP Request
        pkt4 = Ether(src="00:00:00:00:00:03", dst="ff:ff:ff:ff:ff:ff") / \
               ARP(op=1, psrc="10.0.0.3", pdst="10.0.0.1", 
                   hwsrc="00:00:00:00:00:03", hwdst="00:00:00:00:00:00")
        self.packets.append(("ARP Request", pkt4))
        
        # 5. DHCP Discover
        pkt5 = Ether(src="00:00:00:00:00:03", dst="ff:ff:ff:ff:ff:ff") / \
               IP(src="0.0.0.0", dst="255.255.255.255") / \
               UDP(sport=68, dport=67) / \
               BOOTP(chaddr="00:00:00:00:00:03", xid=0x12345678) / \
               DHCP(options=[("message-type", "discover"), "end"])
        self.packets.append(("DHCP Discover", pkt5))
        
        # 6. Custom Protocol (Raw)
        pkt6 = Ether(src="00:00:00:00:00:03", dst="00:00:00:00:00:01") / \
               IP(src="10.0.0.3", dst="10.0.0.1", ttl=64, proto=99) / \
               Raw(b"Custom P4 Protocol Data")
        self.packets.append(("Custom Protocol", pkt6))
        
        print(f"✓ Created {len(self.packets)} advanced protocol packets")
        
    def show_packet_analysis(self, name, packet):
        """Detailed packet analysis"""
        print(f"\n--- {name} ---")
        print(f"Ethernet: {packet[Ether].src} -> {packet[Ether].dst}")
        print(f"EtherType: 0x{packet[Ether].type:04x}")
        
        if IP in packet:
            print(f"IP: {packet[IP].src} -> {packet[IP].dst}")
            print(f"TTL: {packet[IP].ttl}, Protocol: {packet[IP].proto}")
            print(f"Total Length: {packet[IP].len}")
            
        # Protocol-specific analysis
        if ICMP in packet:
            print(f"ICMP: Type={packet[ICMP].type}, Code={packet[ICMP].code}")
            print(f"ID: {packet[ICMP].id}, Seq: {packet[ICMP].seq}")
            
        elif TCP in packet:
            print(f"TCP: {packet[TCP].sport} -> {packet[TCP].dport}")
            print(f"Flags: {packet[TCP].flags}, Seq: {packet[TCP].seq}")
            print(f"Window: {packet[TCP].window}")
            
        elif UDP in packet:
            print(f"UDP: {packet[UDP].sport} -> {packet[UDP].dport}")
            print(f"Length: {packet[UDP].len}")
            
        elif ARP in packet:
            print(f"ARP: {packet[ARP].op} ({'Request' if packet[ARP].op == 1 else 'Reply'})")
            print(f"IP: {packet[ARP].psrc} -> {packet[ARP].pdst}")
            print(f"MAC: {packet[ARP].hwsrc} -> {packet[ARP].hwdst}")
            
        if Raw in packet:
            payload = bytes(packet[Raw])
            print(f"Payload: {payload[:50]}{'...' if len(payload) > 50 else ''}")
            
        print(f"Total Size: {len(packet)} bytes")
        
        # Show detailed packet structure with pkt.show()
        print(f"\n📋 Detailed Packet Structure ({name}):")
        print("=" * 60)
        packet.show()
        print("=" * 60)
        
    def simulate_advanced_p4_processing(self, name, packet):
        """Simulate advanced P4 packet processing"""
        print(f"\n🔄 Processing {name} through P4 pipeline...")
        
        # Stage 1: Parser
        print("  📥 Parser: Extracting headers...")
        ethernet = packet[Ether]
        ip_packet = packet[IP] if IP in packet else None
        
        # Determine protocol type
        protocol_type = "Unknown"
        if ICMP in packet:
            protocol_type = "ICMP"
        elif TCP in packet:
            protocol_type = "TCP"
        elif UDP in packet:
            protocol_type = "UDP"
        elif ARP in packet:
            protocol_type = "ARP"
        elif IP in packet and packet[IP].proto == 99:
            protocol_type = "Custom"
            
        print(f"    Protocol detected: {protocol_type}")
        
        # Stage 2: Ingress Processing
        print("  ⚙️  Ingress: Applying forwarding logic...")
        
        # MAC forwarding
        dst_mac = ethernet.dst
        mac_forwarding_table = {
            "00:00:00:00:00:01": 1,
            "00:00:00:00:00:02": 2,
            "ff:ff:ff:ff:ff:ff": "broadcast"
        }
        
        if dst_mac in mac_forwarding_table:
            output_port = mac_forwarding_table[dst_mac]
            print(f"    ✓ MAC {dst_mac} found -> Forward to port {output_port}")
            mac_action = f"forward(port={output_port})"
        else:
            print(f"    ✗ MAC {dst_mac} not found -> Broadcast")
            mac_action = "broadcast()"
            output_port = "broadcast"
            
        # IP forwarding (if applicable)
        if ip_packet and ip_packet.src != "0.0.0.0":
            dst_ip = ip_packet.dst
            ip_forwarding_table = {
                "10.0.0.1": 1,
                "10.0.0.2": 2,
                "255.255.255.255": "broadcast"
            }
            
            if dst_ip in ip_forwarding_table:
                output_port = ip_forwarding_table[dst_ip]
                print(f"    ✓ IP {dst_ip} found -> Forward to port {output_port}")
                ip_action = f"forward(port={output_port})"
            else:
                print(f"    ✗ IP {dst_ip} not found -> Drop")
                ip_action = "drop()"
        else:
            ip_action = "N/A (no IP or broadcast)"
            
        # Protocol-specific processing
        if protocol_type == "ICMP":
            print("    🔍 ICMP processing: Echo request detected")
        elif protocol_type == "TCP":
            print("    🔍 TCP processing: Connection establishment")
        elif protocol_type == "UDP":
            print("    🔍 UDP processing: Datagram forwarding")
        elif protocol_type == "ARP":
            print("    🔍 ARP processing: Address resolution")
        elif protocol_type == "Custom":
            print("    🔍 Custom protocol: Special handling required")
            
        # TTL processing
        if ip_packet and ip_packet.src != "0.0.0.0":
            old_ttl = ip_packet.ttl
            new_ttl = old_ttl - 1
            print(f"    🔄 TTL decrement: {old_ttl} -> {new_ttl}")
        else:
            new_ttl = "N/A"
            
        # Stage 3: Checksum computation
        if ip_packet and ip_packet.src != "0.0.0.0":
            print("  🔢 Checksum: Recalculating IPv4 header checksum...")
            
        # Stage 4: Deparser
        print("  📤 Deparser: Reconstructing packet...")
        
        # Store processing result
        result = {
            "name": name,
            "protocol": protocol_type,
            "src_mac": ethernet.src,
            "dst_mac": ethernet.dst,
            "src_ip": ip_packet.src if ip_packet else "N/A",
            "dst_ip": ip_packet.dst if ip_packet else "N/A",
            "old_ttl": ip_packet.ttl if ip_packet and ip_packet.src != "0.0.0.0" else "N/A",
            "new_ttl": new_ttl,
            "mac_action": mac_action,
            "ip_action": ip_action,
            "output_port": output_port
        }
        
        self.processing_results.append(result)
        return result
        
    def show_protocol_summary(self):
        """Show summary by protocol type"""
        print("\n" + "="*80)
        print("PROTOCOL-BASED PROCESSING SUMMARY")
        print("="*80)
        
        protocols = {}
        for result in self.processing_results:
            protocol = result['protocol']
            if protocol not in protocols:
                protocols[protocol] = []
            protocols[protocol].append(result)
            
        for protocol, results in protocols.items():
            print(f"\n📡 {protocol} Packets ({len(results)}):")
            for result in results:
                print(f"   {result['name']}: {result['src_mac']}->{result['dst_mac']} | {result['output_port']}")
                
    def show_hex_analysis(self, packet):
        """Show detailed hex analysis"""
        print("\n📋 Detailed Hex Analysis:")
        hexdump(packet, dump=True)
        
        # Show specific field analysis
        print("\n🔍 Field Analysis:")
        if Ether in packet:
            print(f"  Ethernet Header: {packet[Ether].src} -> {packet[Ether].dst}")
        if IP in packet:
            print(f"  IP Header: {packet[IP].src} -> {packet[IP].dst} (TTL: {packet[IP].ttl})")
        if TCP in packet:
            print(f"  TCP Header: {packet[TCP].sport} -> {packet[TCP].dport} (Flags: {packet[TCP].flags})")
        if UDP in packet:
            print(f"  UDP Header: {packet[UDP].sport} -> {packet[UDP].dport}")
            
    def run_advanced_demo(self):
        """Run the advanced demo"""
        print("Advanced P4 Scapy Demo - Multi-Protocol Packet Processing")
        print("=" * 70)
        print("This demo shows packet crafting and processing for various protocols")
        print()
        
        # Create packets
        self.create_protocol_packets()
        
        print("\n" + "="*80)
        print("ADVANCED PACKET GENERATION AND PROCESSING")
        print("="*80)
        
        # Process each packet
        for i, (name, packet) in enumerate(self.packets, 1):
            print(f"\n{'='*20} PACKET {i} {'='*20}")
            
            # Show packet analysis
            self.show_packet_analysis(name, packet)
            
            # Simulate P4 processing
            result = self.simulate_advanced_p4_processing(name, packet)
            
            # Show hex analysis for first packet
            if i == 1:
                self.show_hex_analysis(packet)
            
            time.sleep(1)  # Pause between packets
            
        # Show summaries
        self.show_protocol_summary()
        
        print("\n" + "="*80)
        print("ADVANCED DEMO COMPLETE!")
        print("="*80)
        print("Advanced P4 Concepts Demonstrated:")
        print("✓ Multi-protocol packet parsing (ICMP, TCP, UDP, ARP, DHCP)")
        print("✓ Protocol-specific processing logic")
        print("✓ Advanced table lookups and actions")
        print("✓ Packet modification and checksum recalculation")
        print("✓ Custom protocol handling")
        print("✓ Broadcast and unicast forwarding")
        print()
        print("This demonstrates real-world P4 switch capabilities!")

def main():
    """Main function"""
    demo = AdvancedP4ScapyDemo()
    demo.run_advanced_demo()

if __name__ == "__main__":
    main()
