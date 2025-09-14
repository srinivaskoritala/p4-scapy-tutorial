#!/bin/bash

# P4 Simple L2 Forwarder Demo Setup Script
# This script sets up the environment and demonstrates the P4 program

echo "=========================================="
echo "P4 Simple L2 Forwarder Demo Setup"
echo "=========================================="

# Check if P4 tools are installed
check_p4_tools() {
    echo "Checking for P4 tools..."
    
    if command -v p4c &> /dev/null; then
        echo "✓ p4c compiler found"
    else
        echo "✗ p4c compiler not found"
        echo "  Install with: apt-get install p4c"
        return 1
    fi
    
    if command -v simple_switch &> /dev/null; then
        echo "✓ simple_switch found"
    else
        echo "✗ simple_switch not found"
        echo "  Install with: apt-get install p4lang-bmv2"
        return 1
    fi
    
    return 0
}

# Compile the P4 program
compile_p4() {
    echo ""
    echo "Compiling P4 program..."
    p4c --target bmv2 --arch v1model simple_l2_forward.p4 -o simple_l2_forward.json
    if [ $? -eq 0 ]; then
        echo "✓ P4 program compiled successfully"
        echo "  Output: simple_l2_forward.json"
    else
        echo "✗ P4 compilation failed"
        return 1
    fi
}

# Create table entries
create_table_entries() {
    echo ""
    echo "Creating table entries..."
    
    # Create a Python script to populate tables
    cat > populate_tables.py << 'EOF'
#!/usr/bin/env python3

import json
import socket
import struct

def mac_to_int(mac_str):
    """Convert MAC address string to integer"""
    return int(mac_str.replace(':', ''), 16)

def ip_to_int(ip_str):
    """Convert IP address string to integer"""
    return struct.unpack("!I", socket.inet_aton(ip_str))[0]

# Table entries for MAC forwarding
mac_entries = [
    {
        "table_name": "mac_forwarding",
        "action_name": "forward",
        "match": {"hdr.ethernet.dstAddr": "00:00:00:00:00:01"},
        "action_params": {"port": 1}
    },
    {
        "table_name": "mac_forwarding", 
        "action_name": "forward",
        "match": {"hdr.ethernet.dstAddr": "00:00:00:00:00:02"},
        "action_params": {"port": 2}
    }
]

# Table entries for IP forwarding
ip_entries = [
    {
        "table_name": "ip_forwarding",
        "action_name": "forward", 
        "match": {"hdr.ipv4.dstAddr": "10.0.0.1"},
        "action_params": {"port": 1}
    },
    {
        "table_name": "ip_forwarding",
        "action_name": "forward",
        "match": {"hdr.ipv4.dstAddr": "10.0.0.2"}, 
        "action_params": {"port": 2}
    }
]

print("MAC Forwarding Table Entries:")
for entry in mac_entries:
    print(f"  {entry['match']['hdr.ethernet.dstAddr']} -> port {entry['action_params']['port']}")

print("\nIP Forwarding Table Entries:")
for entry in ip_entries:
    print(f"  {entry['match']['hdr.ipv4.dstAddr']} -> port {entry['action_params']['port']}")

print("\nTable entries created successfully!")
EOF

    chmod +x populate_tables.py
    python3 populate_tables.py
    echo "✓ Table entries created"
}

# Create test packet generator
create_test_packets() {
    echo ""
    echo "Creating test packet generator..."
    
    cat > generate_test_packets.py << 'EOF'
#!/usr/bin/env python3

import struct
import socket

def create_ethernet_header(dst_mac, src_mac, ethertype):
    """Create Ethernet header"""
    dst_bytes = bytes.fromhex(dst_mac.replace(':', ''))
    src_bytes = bytes.fromhex(src_mac.replace(':', ''))
    ethertype_bytes = struct.pack('>H', ethertype)
    return dst_bytes + src_bytes + ethertype_bytes

def create_ipv4_header(src_ip, dst_ip, ttl=64):
    """Create IPv4 header"""
    version_ihl = 0x45  # Version 4, IHL 5
    tos = 0
    total_length = 20  # Header only
    identification = 0
    flags_frag = 0
    ttl_protocol = (ttl << 8) | 1  # TTL + ICMP protocol
    checksum = 0
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    
    # Calculate checksum
    header = struct.pack('>BBHHHBBH4s4s', 
                        version_ihl, tos, total_length, identification,
                        flags_frag, ttl, 1, checksum, src_bytes, dst_bytes)
    
    checksum = calculate_checksum(header)
    header = struct.pack('>BBHHHBBH4s4s',
                        version_ihl, tos, total_length, identification, 
                        flags_frag, ttl, 1, checksum, src_bytes, dst_bytes)
    
    return header

def calculate_checksum(data):
    """Calculate IP checksum"""
    checksum = 0
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            checksum += (data[i] << 8) + data[i + 1]
        else:
            checksum += data[i] << 8
    
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    
    return ~checksum & 0xFFFF

def create_test_packet(dst_mac, src_mac, src_ip, dst_ip):
    """Create a complete test packet"""
    eth_header = create_ethernet_header(dst_mac, src_mac, 0x800)  # IPv4
    ip_header = create_ipv4_header(src_ip, dst_ip)
    payload = b"Hello P4 World!"
    
    return eth_header + ip_header + payload

# Generate test packets
test_packets = [
    {
        "name": "Packet to known MAC",
        "packet": create_test_packet("00:00:00:00:00:01", "00:00:00:00:00:03", 
                                   "10.0.0.3", "10.0.0.1")
    },
    {
        "name": "Packet to unknown MAC", 
        "packet": create_test_packet("00:00:00:00:00:99", "00:00:00:00:00:03",
                                   "10.0.0.3", "10.0.0.99")
    },
    {
        "name": "Packet to known IP",
        "packet": create_test_packet("00:00:00:00:00:02", "00:00:00:00:00:03",
                                   "10.0.0.3", "10.0.0.2")
    }
]

print("Generated test packets:")
for i, test in enumerate(test_packets, 1):
    print(f"  {i}. {test['name']} ({len(test['packet'])} bytes)")

print("\nTest packets created successfully!")
EOF

    chmod +x generate_test_packets.py
    python3 generate_test_packets.py
    echo "✓ Test packet generator created"
}

# Create run demo script
create_demo_script() {
    echo ""
    echo "Creating demo run script..."
    
    cat > run_demo.sh << 'EOF'
#!/bin/bash

echo "=========================================="
echo "Running P4 Simple L2 Forwarder Demo"
echo "=========================================="

# Start the switch
echo "Starting simple_switch..."
simple_switch --interface 0@veth0 --interface 1@veth1 --interface 2@veth2 \
              --log-console --thrift-port 9090 simple_l2_forward.json &
SWITCH_PID=$!

sleep 2

# Populate tables using Python API
echo "Populating forwarding tables..."
python3 << 'PYTHON_EOF'
import subprocess
import time

# Add MAC forwarding entries
subprocess.run([
    'simple_switch_CLI', '--thrift-port', '9090'
], input=b'''
table_add mac_forwarding forward 00:00:00:00:00:01 => 1
table_add mac_forwarding forward 00:00:00:00:00:02 => 2
table_add ip_forwarding forward 10.0.0.1 => 1
table_add ip_forwarding forward 10.0.0.2 => 2
''', check=True)

print("Tables populated successfully!")
PYTHON_EOF

echo ""
echo "Demo setup complete!"
echo ""
echo "Switch is running with PID: $SWITCH_PID"
echo "Thrift port: 9090"
echo ""
echo "To interact with the switch:"
echo "  simple_switch_CLI --thrift-port 9090"
echo ""
echo "To stop the demo:"
echo "  kill $SWITCH_PID"
echo ""
echo "Check the packet path diagram in packet_path_diagram.txt"
echo "Read the explanation in p4_tutorial_explanation.md"

# Keep script running
wait $SWITCH_PID
EOF

    chmod +x run_demo.sh
    echo "✓ Demo run script created"
}

# Main execution
main() {
    echo "Setting up P4 demo environment..."
    
    if ! check_p4_tools; then
        echo "Please install required P4 tools first"
        exit 1
    fi
    
    compile_p4
    create_table_entries
    create_test_packets
    create_demo_script
    
    echo ""
    echo "=========================================="
    echo "Demo setup complete!"
    echo "=========================================="
    echo ""
    echo "Files created:"
    echo "  - simple_l2_forward.p4     (P4 source code)"
    echo "  - simple_l2_forward.json   (Compiled program)"
    echo "  - packet_path_diagram.txt   (Packet flow diagram)"
    echo "  - p4_tutorial_explanation.md (Detailed explanation)"
    echo "  - populate_tables.py        (Table population script)"
    echo "  - generate_test_packets.py  (Test packet generator)"
    echo "  - run_demo.sh              (Demo execution script)"
    echo ""
    echo "To run the demo:"
    echo "  ./run_demo.sh"
    echo ""
    echo "To understand the packet path:"
    echo "  cat packet_path_diagram.txt"
    echo ""
    echo "For detailed explanation:"
    echo "  cat p4_tutorial_explanation.md"
}

main "$@"
