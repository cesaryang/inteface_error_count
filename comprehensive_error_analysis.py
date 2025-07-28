#!/usr/bin/env python3
"""
Comprehensive Cisco Interface Error and CRC Analysis Script
Analyzes error and CRC data from Cisco 'show interface' output with rate filtering

Features:
- Filters out test ports (5-minute rate < 100k packets/sec)
- Calculates (error + crc) / total_packets ratio for each port
- Lists top 10 ports with highest error ratios
- Combines functionality from multiple analysis scripts
"""

import re
import sys
from typing import Dict, List, NamedTuple

class InterfaceData(NamedTuple):
    name: str
    input_packets: int
    output_packets: int
    total_packets: int
    input_rate: int  # packets/sec
    output_rate: int  # packets/sec
    input_errors: int
    crc_errors: int
    frame_errors: int
    overrun_errors: int
    ignored_errors: int
    abort_errors: int
    output_errors: int
    underruns: int
    input_drops: int
    output_drops: int
    error_crc_ratio: float  # (errors + crc) / input_packets
    error_ratio: float
    crc_ratio: float
    output_error_ratio: float  # output_errors / output_packets

def parse_interface_data(filename: str) -> List[InterfaceData]:
    """Parse Cisco interface data and extract all relevant statistics"""
    
    interfaces = []
    current_interface = None
    interface_stats = {}
    
    try:
        with open(filename, 'r') as file:
            lines = file.readlines()
        
        for line in lines:
            line = line.strip()
            
            # Check for interface name (main interfaces and sub-interfaces)
            interface_match = re.match(r'^([A-Za-z][A-Za-z0-9\-\.\/]+)\s+is\s+(up|down)', line)
            if interface_match:
                current_interface = interface_match.group(1)
                interface_stats[current_interface] = {
                    'name': current_interface,
                    'input_packets': 0,
                    'output_packets': 0,
                    'input_rate': 0,
                    'output_rate': 0,
                    'input_errors': 0,
                    'crc_errors': 0,
                    'frame_errors': 0,
                    'overrun_errors': 0,
                    'ignored_errors': 0,
                    'abort_errors': 0,
                    'output_errors': 0,
                    'underruns': 0,
                    'input_drops': 0,
                    'output_drops': 0
                }
                continue
            
            if current_interface and current_interface in interface_stats:
                # Parse 5-minute input rate
                input_rate_match = re.search(r'5 minute input rate.*?(\d+) packets/sec', line)
                if input_rate_match:
                    interface_stats[current_interface]['input_rate'] = int(input_rate_match.group(1))
                    continue
                
                # Parse 5-minute output rate
                output_rate_match = re.search(r'5 minute output rate.*?(\d+) packets/sec', line)
                if output_rate_match:
                    interface_stats[current_interface]['output_rate'] = int(output_rate_match.group(1))
                    continue
                
                # Parse input packets
                input_packets_match = re.search(r'(\d+) packets input.*?(\d+) total input drops', line)
                if input_packets_match:
                    interface_stats[current_interface]['input_packets'] = int(input_packets_match.group(1))
                    interface_stats[current_interface]['input_drops'] = int(input_packets_match.group(2))
                    continue
                
                # Parse output packets
                output_packets_match = re.search(r'(\d+) packets output.*?(\d+) total output drops', line)
                if output_packets_match:
                    interface_stats[current_interface]['output_packets'] = int(output_packets_match.group(1))
                    interface_stats[current_interface]['output_drops'] = int(output_packets_match.group(2))
                    continue
                
                # Parse error statistics line
                error_match = re.search(r'(\d+) input errors, (\d+) CRC, (\d+) frame, (\d+) overrun, (\d+) ignored, (\d+) abort', line)
                if error_match:
                    interface_stats[current_interface]['input_errors'] = int(error_match.group(1))
                    interface_stats[current_interface]['crc_errors'] = int(error_match.group(2))
                    interface_stats[current_interface]['frame_errors'] = int(error_match.group(3))
                    interface_stats[current_interface]['overrun_errors'] = int(error_match.group(4))
                    interface_stats[current_interface]['ignored_errors'] = int(error_match.group(5))
                    interface_stats[current_interface]['abort_errors'] = int(error_match.group(6))
                    continue
                
                # Parse output errors
                output_error_match = re.search(r'(\d+) output errors, (\d+) underruns', line)
                if output_error_match:
                    interface_stats[current_interface]['output_errors'] = int(output_error_match.group(1))
                    interface_stats[current_interface]['underruns'] = int(output_error_match.group(2))
                    continue
        
        # Process parsed data and apply filters
        for name, data in interface_stats.items():
            # Skip interfaces with no packet traffic
            total_packets = data['input_packets'] + data['output_packets']
            if total_packets == 0:
                continue
            
            # Apply rate filter: exclude test ports (rate < 100k/sec)
            max_rate = max(data['input_rate'], data['output_rate'])
            if max_rate < 100000:  # 100k packets/sec threshold
                continue
            
            # Calculate ratios based on input packets only (not combined)
            error_crc_sum = data['input_errors'] + data['crc_errors']
            error_crc_ratio = (error_crc_sum / data['input_packets']) * 100 if data['input_packets'] > 0 else 0
            error_ratio = (data['input_errors'] / data['input_packets']) * 100 if data['input_packets'] > 0 else 0
            crc_ratio = (data['crc_errors'] / data['input_packets']) * 100 if data['input_packets'] > 0 else 0
            
            # Calculate output error ratio
            output_error_ratio = (data['output_errors'] / data['output_packets']) * 100 if data['output_packets'] > 0 else 0
            
            interface_data = InterfaceData(
                name=data['name'],
                input_packets=data['input_packets'],
                output_packets=data['output_packets'],
                total_packets=total_packets,
                input_rate=data['input_rate'],
                output_rate=data['output_rate'],
                input_errors=data['input_errors'],
                crc_errors=data['crc_errors'],
                frame_errors=data['frame_errors'],
                overrun_errors=data['overrun_errors'],
                ignored_errors=data['ignored_errors'],
                abort_errors=data['abort_errors'],
                output_errors=data['output_errors'],
                underruns=data['underruns'],
                input_drops=data['input_drops'],
                output_drops=data['output_drops'],
                error_crc_ratio=error_crc_ratio,
                error_ratio=error_ratio,
                crc_ratio=crc_ratio,
                output_error_ratio=output_error_ratio
            )
            
            interfaces.append(interface_data)
    
    except FileNotFoundError:
        print(f"Error: File {filename} not found")
        return []
    except Exception as e:
        print(f"Error parsing file: {e}")
        return []
    
    return interfaces

def print_top_10_analysis(interfaces: List[InterfaceData]):
    """Print top 10 interfaces with highest (error + crc) / total_packets ratio"""
    
    if not interfaces:
        print("No qualifying interface data found (after filtering test ports).")
        return
    
    # Filter interfaces that have errors or CRC issues
    problem_interfaces = [i for i in interfaces if i.error_crc_ratio > 0]
    
    # Sort by (error + crc) / total_packets ratio descending
    sorted_interfaces = sorted(problem_interfaces, key=lambda x: x.error_crc_ratio, reverse=True)
    
    print("=" * 120)
    print("COMPREHENSIVE CISCO INTERFACE ERROR AND CRC ANALYSIS")
    print("=" * 120)
    print("Analysis of high-traffic interfaces (5-min rate ≥ 100k packets/sec)")
    print("Showing (Error + CRC) / Input_Packets ratio")
    print("=" * 120)
    
    # Summary statistics
    total_analyzed = len(interfaces)
    total_with_issues = len(problem_interfaces)
    
    print(f"\nSUMMARY:")
    print(f"Total high-traffic interfaces analyzed: {total_analyzed}")
    print(f"Interfaces with error/CRC issues: {total_with_issues}")
    print(f"Percentage with issues: {(total_with_issues/total_analyzed*100):.1f}%")
    
    print(f"\nTOP 10 INTERFACES BY (ERROR + CRC) / INPUT_PACKETS RATIO:")
    print("-" * 80)
    
    header = f"{'Rank':<4} {'Interface':<25} {'(E+CRC)%':<12} {'Error+CRC':<12} {'Input Pkts':<15} {'Status':<10}"
    print(header)
    print("-" * 80)
    
    top_10 = sorted_interfaces[:10]
    
    for i, interface in enumerate(top_10, 1):
        # Determine severity status
        if interface.error_crc_ratio > 1.0:
            status = "CRITICAL"
        elif interface.error_crc_ratio > 0.1:
            status = "HIGH"
        elif interface.error_crc_ratio > 0.01:
            status = "MEDIUM"
        else:
            status = "LOW"
        
        error_crc_sum = interface.input_errors + interface.crc_errors
        
        row = f"{i:<4} {interface.name:<25} {interface.error_crc_ratio:<12.6f} {error_crc_sum:<12,} {interface.input_packets:<15,} {status:<10}"
        print(row)
    
    print(f"\nDETAILED BREAKDOWN OF TOP 10:")
    print("-" * 80)
    
    for i, interface in enumerate(top_10, 1):
        error_crc_sum = interface.input_errors + interface.crc_errors
        
        print(f"\n{i}. Interface: {interface.name}")
        print(f"   Input Packets:        {interface.input_packets:,}")
        print(f"   Input Errors:         {interface.input_errors:,}")
        print(f"   CRC Errors:           {interface.crc_errors:,}")
        print(f"   Error + CRC Sum:      {error_crc_sum:,}")
        print(f"   (Error+CRC)/Input:    {interface.error_crc_ratio:.6f}%")
        print(f"   Error/Input Ratio:    {interface.error_ratio:.6f}%")
        print(f"   CRC/Input Ratio:      {interface.crc_ratio:.6f}%")
        
        if interface.frame_errors > 0:
            print(f"   Frame Errors:         {interface.frame_errors:,}")
        if interface.output_errors > 0:
            print(f"   Output Errors:        {interface.output_errors:,}")
        if interface.input_drops > 0 or interface.output_drops > 0:
            print(f"   Input Drops:          {interface.input_drops:,}")
            print(f"   Output Drops:         {interface.output_drops:,}")

def print_top_5_output_errors(interfaces: List[InterfaceData]):
    """Print top 5 interfaces with highest output error ratios"""
    
    # Filter interfaces that have output errors
    output_error_interfaces = [i for i in interfaces if i.output_error_ratio > 0]
    
    if not output_error_interfaces:
        print(f"\nNO OUTPUT ERRORS FOUND")
        print("=" * 50)
        print("All high-traffic interfaces have 0 output errors.")
        return
    
    # Sort by output error ratio descending
    sorted_output_errors = sorted(output_error_interfaces, key=lambda x: x.output_error_ratio, reverse=True)
    
    print(f"\nTOP 5 INTERFACES BY OUTPUT ERROR RATIO:")
    print("=" * 80)
    print("Analysis of interfaces with output errors / output_packets")
    print("=" * 80)
    
    header = f"{'Rank':<4} {'Interface':<25} {'Output Err%':<12} {'Output Errors':<15} {'Output Pkts':<15} {'Status':<10}"
    print(header)
    print("-" * 80)
    
    top_5_output = sorted_output_errors[:5]
    
    for i, interface in enumerate(top_5_output, 1):
        # Determine severity status for output errors
        if interface.output_error_ratio > 1.0:
            status = "CRITICAL"
        elif interface.output_error_ratio > 0.1:
            status = "HIGH"
        elif interface.output_error_ratio > 0.01:
            status = "MEDIUM"
        else:
            status = "LOW"
        
        row = f"{i:<4} {interface.name:<25} {interface.output_error_ratio:<12.6f} {interface.output_errors:<15,} {interface.output_packets:<15,} {status:<10}"
        print(row)
    
    print(f"\nDETAILED BREAKDOWN OF TOP 5 OUTPUT ERROR INTERFACES:")
    print("-" * 80)
    
    for i, interface in enumerate(top_5_output, 1):
        print(f"\n{i}. Interface: {interface.name}")
        print(f"   Output Packets:       {interface.output_packets:,}")
        print(f"   Output Errors:        {interface.output_errors:,}")
        print(f"   Output Error Ratio:   {interface.output_error_ratio:.6f}%")
        print(f"   Underruns:            {interface.underruns:,}")
        if interface.output_drops > 0:
            print(f"   Output Drops:         {interface.output_drops:,}")

def print_complete_analysis(interfaces: List[InterfaceData]):
    """Print complete analysis similar to existing scripts"""
    
    if not interfaces:
        return
    
    print(f"\n\n" + "=" * 100)
    print("COMPLETE HIGH-TRAFFIC INTERFACE ANALYSIS")
    print("=" * 100)
    print("All interfaces with 5-minute rate ≥ 100k packets/sec, sorted by error+CRC ratio")
    print("=" * 100)
    
    # Sort all interfaces by error_crc_ratio
    all_sorted = sorted(interfaces, key=lambda x: x.error_crc_ratio, reverse=True)
    
    header = f"{'Interface':<25} {'Input Pkts':<15} {'E+CRC':<10} {'(E+CRC)%':<12} {'Classification':<15}"
    print(header)
    print("-" * 80)
    
    for interface in all_sorted:
        error_crc_sum = interface.input_errors + interface.crc_errors
        
        if interface.error_crc_ratio > 0.1:
            classification = "CRITICAL"
        elif interface.error_crc_ratio > 0.01:
            classification = "HIGH"
        elif interface.error_crc_ratio > 0.001:
            classification = "MEDIUM"
        elif error_crc_sum > 0:
            classification = "LOW"
        else:
            classification = "GOOD"
        
        row = f"{interface.name:<25} {interface.input_packets:<15,} {error_crc_sum:<10,} {interface.error_crc_ratio:<12.6f} {classification:<15}"
        print(row)
    
    # Network-wide statistics
    print(f"\n" + "=" * 80)
    print("NETWORK-WIDE STATISTICS (High-Traffic Interfaces Only)")
    print("=" * 80)
    
    total_input_packets = sum(i.input_packets for i in interfaces)
    total_output_packets = sum(i.output_packets for i in interfaces)
    total_input_errors = sum(i.input_errors for i in interfaces)
    total_crc_errors = sum(i.crc_errors for i in interfaces)
    total_output_errors = sum(i.output_errors for i in interfaces)
    total_input_drops = sum(i.input_drops for i in interfaces)
    total_output_drops = sum(i.output_drops for i in interfaces)
    
    overall_error_crc_ratio = ((total_input_errors + total_crc_errors) / total_input_packets) * 100 if total_input_packets > 0 else 0
    
    print(f"Total Input Packets:      {total_input_packets:,}")
    print(f"Total Output Packets:     {total_output_packets:,}")
    print(f"Total Input Errors:       {total_input_errors:,}")
    print(f"Total CRC Errors:         {total_crc_errors:,}")
    print(f"Total Output Errors:      {total_output_errors:,}")
    print(f"Total Input Drops:        {total_input_drops:,}")
    print(f"Total Output Drops:       {total_output_drops:,}")
    print(f"Overall (Error+CRC)/Input Rate: {overall_error_crc_ratio:.6f}%")

def main():
    """Main function to run the comprehensive analysis"""
    
    # Allow filename to be passed as command line argument
    import sys
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    else:
        filename = "/home/ec2-user/int_error/int_error.txt"
    
    print(f"Parsing Cisco interface data from {filename}...")
    print("Filtering out test ports (5-minute rate < 100k packets/sec)...")
    
    interfaces = parse_interface_data(filename)
    
    if interfaces:
        print(f"Successfully parsed {len(interfaces)} high-traffic interfaces.")
        print_top_10_analysis(interfaces)
        print_top_5_output_errors(interfaces)
        print_complete_analysis(interfaces)
    else:
        print("No interface data could be parsed from the file.")
    
    print(f"\n" + "=" * 80)
    print("ANALYSIS COMPLETE")
    print("=" * 80)

if __name__ == "__main__":
    main()