# P4 Programming Tutorial: Simple L2 Forwarder

A practical P4 tutorial demonstrating packet processing with a simple L2 forwarder.

## Files

- `simple_l2_forward.p4` - Main P4 program
- `packet_path_diagram.txt` - Packet flow visualization  
- `p4_tutorial_explanation.md` - Detailed P4 concepts
- `demo_setup.sh` - Setup script
- `packet_trace_visualizer.py` - Interactive demo
- `README.md` - This file

## Quick Start

```bash
# Setup and run demo
chmod +x demo_setup.sh
./demo_setup.sh
./run_demo.sh

# Visualize packet flow
python3 packet_trace_visualizer.py
```

## What You'll Learn

- P4 language basics (headers, parsers, tables, actions)
- Packet processing pipeline
- L2 forwarding implementation
- Interactive packet trace visualization

## Prerequisites

- p4c compiler
- simple_switch (BMv2)
- Python 3

## Installation

```bash
sudo apt-get install p4c p4lang-bmv2
```

## Program Features

- MAC address forwarding
- IP address forwarding  
- Broadcast for unknown destinations
- TTL decrement and checksum recalculation
- Packet dropping for unmatched rules

## Demo Scenarios

1. Known MAC forwarding
2. Unknown MAC broadcasting
3. Known IP forwarding

Happy P4 Programming! 🚀