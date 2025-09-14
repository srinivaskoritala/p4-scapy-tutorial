# P4 Programming Tutorial: Protocol-Independent Packet Processors

## What is P4?

P4 (Programming Protocol-Independent Packet Processors) is a domain-specific language for programming the data plane of network devices. It allows you to define:

1. **What headers to parse** from incoming packets
2. **How to process** those headers 
3. **What actions to take** based on the processing results
4. **How to construct** outgoing packets

## Key P4 Concepts

### 1. Headers
Headers define the structure of packet fields that you want to process:

```p4
header ethernet_t {
    macAddr_t dstAddr;    // 48-bit destination MAC
    macAddr_t srcAddr;    // 48-bit source MAC  
    bit<16>   etherType;  // 16-bit EtherType
}
```

### 2. Parser
The parser extracts headers from raw packet data in a state machine:

```p4
state parse_ethernet {
    packet.extract(hdr.ethernet);
    transition select(hdr.ethernet.etherType) {
        0x800: parse_ipv4;  // If IPv4, parse IP header
        default: accept;    // Otherwise, stop parsing
    }
}
```

### 3. Tables
Tables store forwarding rules and actions:

```p4
table mac_forwarding {
    key = {
        hdr.ethernet.dstAddr: exact;  // Match exact MAC address
    }
    actions = {
        forward;    // Forward to specific port
        broadcast;  // Broadcast to all ports
        drop;       // Drop packet
    }
    size = 1024;  // Table can hold 1024 entries
}
```

### 4. Actions
Actions define what to do with packets:

```p4
action forward(bit<9> port) {
    standard_metadata.egress_spec = port;  // Set output port
}

action drop() {
    mark_to_drop(standard_metadata);  // Mark packet for dropping
}
```

### 5. Control Flow
The control block applies tables and actions:

```p4
apply {
    if (hdr.ethernet.isValid()) {
        mac_forwarding.apply();  // Apply MAC forwarding table
    }
    
    if (hdr.ipv4.isValid()) {
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;  // Decrement TTL
        ip_forwarding.apply();  // Apply IP forwarding table
    }
}
```

## Packet Processing Pipeline

Our simple L2 forwarder follows this pipeline:

1. **Parser**: Extract Ethernet and IPv4 headers
2. **Verify Checksum**: Validate packet integrity (optional)
3. **Ingress Processing**: Apply forwarding tables and modify packet
4. **Egress Processing**: Post-process before transmission
5. **Compute Checksum**: Recalculate checksums after modifications
6. **Deparser**: Reconstruct packet for output

## Program Structure

The P4 program is organized into several main components:

### Headers Section
- Define packet header structures
- Specify field types and sizes

### Parser
- State machine to extract headers
- Determines which headers to parse based on packet content

### Control Blocks
- **Ingress**: Main packet processing logic
- **Egress**: Post-processing before transmission
- **Verify/Compute Checksum**: Handle packet integrity

### Deparser
- Reconstructs packet from processed headers
- Emits headers in correct order

## Example Use Cases

This simple program demonstrates:

1. **L2 Forwarding**: Forward packets based on MAC addresses
2. **L3 Forwarding**: Forward packets based on IP addresses  
3. **Broadcasting**: Send unknown destinations to all ports
4. **TTL Processing**: Decrement IP TTL and recalculate checksum
5. **Packet Dropping**: Drop packets that don't match any rules

## Key Benefits of P4

1. **Protocol Independence**: Define your own packet processing logic
2. **Flexibility**: Modify behavior without changing hardware
3. **Abstraction**: High-level programming model for network data plane
4. **Portability**: Same program can run on different P4 targets
5. **Verification**: Formal verification of packet processing logic

## Next Steps

To run this program:

1. Compile with a P4 compiler (e.g., p4c)
2. Load onto a P4 target (e.g., BMv2, Tofino)
3. Populate tables with forwarding rules
4. Send test packets and observe behavior

This example provides a foundation for understanding P4 programming and can be extended with more complex forwarding logic, additional protocols, and advanced features like stateful processing.

