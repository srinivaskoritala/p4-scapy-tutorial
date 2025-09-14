# P4 Programming Tutorial with Scapy Packet Crafting

A comprehensive tutorial demonstrating P4 (Programming Protocol-Independent Packet Processors) with real packet generation and processing using Scapy.

## 🚀 Overview

This repository contains a complete P4 programming tutorial that shows:
- **P4 Language Basics**: Headers, parsers, tables, actions, and control flow
- **Real Packet Crafting**: Using Scapy to create actual network packets
- **Multi-Protocol Support**: ICMP, TCP, UDP, ARP, DHCP packet processing
- **Interactive Visualization**: Step-by-step packet processing pipeline
- **Packet Analysis**: Detailed packet inspection with `pkt.show()`

## 📁 Repository Contents

### Core P4 Program
- `simple_l2_forward.p4` - Working P4 L2 forwarder with MAC/IP forwarding

### Scapy Demos
- `simple_scapy_demo.py` - Basic packet crafting and P4 processing simulation
- `advanced_scapy_demo.py` - Multi-protocol packet processing (ICMP, TCP, UDP, ARP, DHCP)
- `conntrack_scapy_demo.py` - Connection tracking with 1000-entry conntrack table
- `conntrack_5tuple_demo.py` - Proper 5-tuple connection tracking (src_ip:dst_ip:protocol:src_port:dst_port)
- `scapy_packet_demo.py` - Full network interface demo (requires root)

### Visualization & Learning
- `packet_trace_visualizer.py` - Interactive packet processing visualization
- `packet_path_diagram.txt` - ASCII diagram of P4 pipeline
- `p4_tutorial_explanation.md` - Comprehensive P4 concepts guide

### Demo Management
- `run_all_demos.sh` - Runs all demos in sequence
- `demo_setup.sh` - Environment setup and P4 compilation
- `requirements.txt` - Python dependencies

## 🎯 Key Features

### Packet Generation with Scapy
```python
# ICMP Echo Request
pkt = Ether(src="00:00:00:00:00:03", dst="00:00:00:00:00:01") / \
      IP(src="10.0.0.3", dst="10.0.0.1", ttl=64) / \
      ICMP(type=8, code=0) / \
      Raw(b"Hello P4 World!")

# Show detailed packet structure
pkt.show()
```

### P4 Pipeline Processing
```
Packet In → Parser → Verify → Ingress → Egress → Compute Checksum → Deparser → Packet Out
```

### Multi-Protocol Support
- ✅ **ICMP Echo Requests** - Ping packets with custom payloads
- ✅ **TCP SYN Packets** - Connection establishment packets  
- ✅ **UDP DNS Queries** - DNS resolution packets
- ✅ **ARP Requests** - Address resolution packets
- ✅ **DHCP Discover** - Network configuration packets
- ✅ **Custom Protocols** - User-defined protocol handling

### Connection Tracking Features
- ✅ **1000-Entry Conntrack Table** - Large-scale connection state management
- ✅ **5-Tuple Connection ID** - Proper format: src_ip:dst_ip:protocol:src_port:dst_port
- ✅ **Connection State Tracking** - NEW, ESTABLISHED, SYN_SENT states
- ✅ **Packet Counting** - Track packets per connection
- ✅ **State Transitions** - Automatic state updates based on packet types
- ✅ **Connection Lookup** - Fast hash-based connection retrieval
- ✅ **Port-Based Differentiation** - Separate connections by source/destination ports

## 🛠 Quick Start

### Prerequisites
```bash
# Install P4 tools
sudo apt-get install p4c p4lang-bmv2

# Install Python dependencies
sudo apt-get install python3-scapy
```

### Run Demos
```bash
# Run all demos
./run_all_demos.sh

# Individual demos
python3 simple_scapy_demo.py      # Basic packet processing
python3 advanced_scapy_demo.py    # Multi-protocol demo
python3 conntrack_scapy_demo.py   # Connection tracking demo
python3 conntrack_5tuple_demo.py  # 5-tuple connection tracking demo
python3 packet_trace_visualizer.py # Interactive visualization
```

## 📊 Demo Output

### Packet Structure Analysis
```
📋 Detailed Packet Structure (ICMP Echo Request):
==================================================
###[ Ethernet ]### 
  dst       = 00:00:00:00:00:01
  src       = 00:00:00:00:00:03
  type      = IPv4
###[ IP ]### 
     version   = 4
     ihl       = None
     tos       = 0x0
     len       = None
     id        = 1
     flags     = 
     frag      = 0
     ttl       = 64
     proto     = icmp
     chksum    = None
     src       = 10.0.0.3
     dst       = 10.0.0.1
###[ ICMP ]### 
        type      = echo-request
        code      = 0
        chksum    = None
        id        = 0x0
        seq       = 0x0
```

### P4 Processing Pipeline
```
🔄 Processing ICMP Echo Request through P4 pipeline...
  📥 Parser: Extracting headers...
    Protocol detected: ICMP
  ⚙️  Ingress: Applying forwarding logic...
    ✓ MAC 00:00:00:00:00:01 found -> Forward to port 1
    ✓ IP 10.0.0.1 found -> Forward to port 1
    🔍 ICMP processing: Echo request detected
    🔄 TTL decrement: 64 -> 63
  🔢 Checksum: Recalculating IPv4 header checksum...
  📤 Deparser: Reconstructing packet...
```

## 🎓 Learning Objectives

After completing this tutorial, you will understand:

1. **P4 Language Fundamentals**
   - Header definitions and parsing
   - Table-driven forwarding logic
   - Action execution and packet modification
   - Pipeline processing stages

2. **Packet Crafting with Scapy**
   - Creating various protocol packets
   - Packet structure inspection
   - Protocol-specific field manipulation

3. **Network Programming Concepts**
   - Packet processing pipelines
   - Table lookups and forwarding decisions
   - Checksum calculation and validation
   - Multi-protocol handling

## 🔧 Advanced Usage

### Custom Protocol Handling
```python
# Create custom protocol packet
pkt = Ether(src="00:00:00:00:00:03", dst="00:00:00:00:00:01") / \
      IP(src="10.0.0.3", dst="10.0.0.1", ttl=64, proto=99) / \
      Raw(b"Custom P4 Protocol Data")
```

### P4 Table Population
```bash
# Add forwarding rules
table_add mac_forwarding forward 00:00:00:00:00:01 => 1
table_add ip_forwarding forward 10.0.0.1 => 1
```

## 📚 Resources

- [P4.org Official Website](https://p4.org/)
- [P4 Language Specification](https://p4.org/p4-spec/)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [BMv2 Documentation](https://github.com/p4lang/behavioral-model)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👨‍💻 Author

**srinivaskoritala** - [GitHub Profile](https://github.com/srinivaskoritala)

---

**Happy P4 Programming!** 🚀