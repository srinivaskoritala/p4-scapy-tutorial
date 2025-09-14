#!/bin/bash

# P4 Complete Demo Suite
# This script runs all P4 demos in sequence

echo "=========================================="
echo "P4 Complete Demo Suite"
echo "=========================================="
echo "This will run all P4 demos to show packet processing"
echo ""

# Function to run demo with pause
run_demo() {
    local demo_name="$1"
    local demo_script="$2"
    
    echo "Running: $demo_name"
    echo "----------------------------------------"
    python3 "$demo_script"
    echo ""
    echo "Press Enter to continue to next demo..."
    read -r
    echo ""
}

# Check if Scapy is available
if ! python3 -c "import scapy" 2>/dev/null; then
    echo "Scapy not found. Installing..."
    sudo apt-get install -y python3-scapy
fi

echo "Starting P4 Demo Suite..."
echo ""

# Demo 1: Basic packet trace visualization
run_demo "Basic Packet Trace Visualization" "packet_trace_visualizer.py"

# Demo 2: Simple Scapy packet generation and processing
run_demo "Simple Scapy Packet Demo" "simple_scapy_demo.py"

# Demo 3: Advanced multi-protocol packet processing
run_demo "Advanced Multi-Protocol Demo" "advanced_scapy_demo.py"

# Demo 4: Connection tracking with 1000-entry table
run_demo "Connection Tracking Demo" "conntrack_scapy_demo.py"

echo "=========================================="
echo "ALL DEMOS COMPLETE!"
echo "=========================================="
echo ""
echo "You have seen:"
echo "✓ P4 packet processing pipeline visualization"
echo "✓ Real packet crafting with Scapy"
echo "✓ Multi-protocol packet processing (ICMP, TCP, UDP, ARP, DHCP)"
echo "✓ Connection tracking with 1000-entry conntrack table"
echo "✓ Table lookups and forwarding decisions"
echo "✓ Packet modification and checksum recalculation"
echo "✓ Custom protocol handling"
echo "✓ Connection state management and packet counting"
echo ""
echo "Files created:"
echo "  - simple_l2_forward.p4          (P4 source code)"
echo "  - packet_path_diagram.txt       (Pipeline visualization)"
echo "  - p4_tutorial_explanation.md    (Detailed explanation)"
echo "  - simple_scapy_demo.py          (Basic Scapy demo)"
echo "  - advanced_scapy_demo.py        (Advanced Scapy demo)"
echo "  - packet_trace_visualizer.py    (Interactive visualization)"
echo "  - demo_setup.sh                 (Environment setup)"
echo ""
echo "To run individual demos:"
echo "  python3 simple_scapy_demo.py"
echo "  python3 advanced_scapy_demo.py"
echo "  python3 packet_trace_visualizer.py"
echo ""
echo "Happy P4 Programming! 🚀"
