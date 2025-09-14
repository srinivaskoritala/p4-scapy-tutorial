#!/usr/bin/env python3

"""
P4 Packet Trace Visualizer
Shows how packets flow through the P4 pipeline
"""

import time
import struct

class PacketTraceVisualizer:
    def __init__(self):
        self.stages = [
            "PACKET IN",
            "PARSER", 
            "VERIFY CHECKSUM",
            "INGRESS PROCESSING",
            "EGRESS PROCESSING", 
            "COMPUTE CHECKSUM",
            "DEPARSER",
            "PACKET OUT"
        ]
        
    def visualize_packet_flow(self, packet_info):
        """Visualize packet flow through P4 pipeline"""
        print("=" * 80)
        print("P4 PACKET PROCESSING TRACE")
        print("=" * 80)
        print()
        
        # Show packet details
        print(f"Packet: {packet_info['name']}")
        print(f"Size: {packet_info['size']} bytes")
        print(f"Source MAC: {packet_info['src_mac']}")
        print(f"Dest MAC: {packet_info['dst_mac']}")
        print(f"Source IP: {packet_info['src_ip']}")
        print(f"Dest IP: {packet_info['dst_ip']}")
        print()
        
        # Show pipeline stages
        for i, stage in enumerate(self.stages):
            self._show_stage(i, stage, packet_info)
            time.sleep(0.5)  # Animation effect
            
    def _show_stage(self, stage_num, stage_name, packet_info):
        """Show individual pipeline stage"""
        print(f"Stage {stage_num + 1}: {stage_name}")
        print("-" * 40)
        
        if stage_name == "PACKET IN":
            print("Raw packet received from network interface")
            print(f"  Ethernet: {packet_info['dst_mac']} -> {packet_info['src_mac']}")
            print(f"  IPv4: {packet_info['src_ip']} -> {packet_info['dst_ip']}")
            
        elif stage_name == "PARSER":
            print("Extracting headers from packet:")
            print("  ✓ Ethernet header parsed (14 bytes)")
            print("  ✓ IPv4 header parsed (20 bytes)")
            print("  ✓ EtherType = 0x800 (IPv4)")
            
        elif stage_name == "VERIFY CHECKSUM":
            print("Verifying packet integrity:")
            print("  ✓ IPv4 header checksum valid")
            
        elif stage_name == "INGRESS PROCESSING":
            print("Applying forwarding logic:")
            print("  → Checking MAC forwarding table...")
            
            # Simulate table lookup
            if packet_info['dst_mac'] in ['00:00:00:00:00:01', '00:00:00:00:00:02']:
                port = '1' if packet_info['dst_mac'] == '00:00:00:00:00:01' else '2'
                print(f"  ✓ MAC {packet_info['dst_mac']} found -> Forward to port {port}")
            else:
                print(f"  ✗ MAC {packet_info['dst_mac']} not found -> Broadcast")
                
            print("  → Checking IP forwarding table...")
            if packet_info['dst_ip'] in ['10.0.0.1', '10.0.0.2']:
                port = '1' if packet_info['dst_ip'] == '10.0.0.1' else '2'
                print(f"  ✓ IP {packet_info['dst_ip']} found -> Forward to port {port}")
            else:
                print(f"  ✗ IP {packet_info['dst_ip']} not found -> Drop")
                
            print("  → Decrementing TTL: 64 -> 63")
            
        elif stage_name == "EGRESS PROCESSING":
            print("Post-processing before transmission:")
            print("  ✓ No additional processing needed")
            
        elif stage_name == "COMPUTE CHECKSUM":
            print("Recalculating checksums:")
            print("  ✓ IPv4 header checksum updated (TTL changed)")
            
        elif stage_name == "DEPARSER":
            print("Reconstructing packet:")
            print("  ✓ Ethernet header emitted")
            print("  ✓ IPv4 header emitted (with new checksum)")
            print("  ✓ Payload preserved")
            
        elif stage_name == "PACKET OUT":
            print("Packet transmitted to output port")
            if packet_info['dst_mac'] in ['00:00:00:00:00:01', '00:00:00:00:00:02']:
                port = '1' if packet_info['dst_mac'] == '00:00:00:00:00:01' else '2'
                print(f"  → Sent to port {port}")
            else:
                print("  → Broadcast to all ports")
                
        print()

def create_sample_packets():
    """Create sample packets for demonstration"""
    return [
        {
            "name": "Packet to Known MAC",
            "size": 64,
            "src_mac": "00:00:00:00:00:03",
            "dst_mac": "00:00:00:00:00:01", 
            "src_ip": "10.0.0.3",
            "dst_ip": "10.0.0.1"
        },
        {
            "name": "Packet to Unknown MAC",
            "size": 64,
            "src_mac": "00:00:00:00:00:03",
            "dst_mac": "00:00:00:00:00:99",
            "src_ip": "10.0.0.3", 
            "dst_ip": "10.0.0.99"
        },
        {
            "name": "Packet to Known IP",
            "size": 64,
            "src_mac": "00:00:00:00:00:03",
            "dst_mac": "00:00:00:00:00:02",
            "src_ip": "10.0.0.3",
            "dst_ip": "10.0.0.2"
        }
    ]

def main():
    """Main demonstration function"""
    print("P4 Packet Trace Visualizer")
    print("=========================")
    print()
    
    visualizer = PacketTraceVisualizer()
    packets = create_sample_packets()
    
    for i, packet in enumerate(packets, 1):
        print(f"Demo {i}: {packet['name']}")
        print()
        visualizer.visualize_packet_flow(packet)
        
        if i < len(packets):
            input("Press Enter to continue to next packet...")
            print("\n" + "="*80 + "\n")
    
    print("Demo complete!")
    print()
    print("Key Takeaways:")
    print("- P4 programs define packet processing pipelines")
    print("- Each stage has a specific purpose in packet handling")
    print("- Tables store forwarding rules and actions")
    print("- Packets can be modified as they flow through the pipeline")
    print("- The same program can handle different packet types")

if __name__ == "__main__":
    main()
