from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
import argparse
import sys
from datetime import datetime
import json

class NetworkSniffer:
    def __init__(self, interface=None, count=0, filter_protocol=None):
        self.interface = interface
        self.count = count
        self.filter_protocol = filter_protocol
        self.packet_count = 0
        self.captured_packets = []
        
    def packet_handler(self, packet):
        """Process each captured packet"""
        self.packet_count += 1
        
        # Extract basic packet information
        packet_info = {
            'packet_number': self.packet_count,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'size': len(packet)
        }
        
        # Analyze different protocol layers
        if IP in packet:
            self.analyze_ip_packet(packet, packet_info)
        elif ARP in packet:
            self.analyze_arp_packet(packet, packet_info)
        else:
            packet_info['protocol'] = 'Other'
            packet_info['summary'] = packet.summary()
            
        # Store packet info
        self.captured_packets.append(packet_info)
        
        # Display packet information
        self.display_packet_info(packet_info)
        
    def analyze_ip_packet(self, packet, packet_info):
        """Analyze IP layer packets"""
        ip_layer = packet[IP]
        
        packet_info.update({
            'src_ip': ip_layer.src,
            'dst_ip': ip_layer.dst,
            'ip_version': ip_layer.version,
            'ttl': ip_layer.ttl,
            'ip_length': ip_layer.len
        })
        
        # Analyze transport layer protocols
        if TCP in packet:
            self.analyze_tcp_packet(packet, packet_info)
        elif UDP in packet:
            self.analyze_udp_packet(packet, packet_info)
        elif ICMP in packet:
            self.analyze_icmp_packet(packet, packet_info)
        else:
            packet_info['protocol'] = f'IP ({ip_layer.proto})'
            
    def analyze_tcp_packet(self, packet, packet_info):
        """Analyze TCP packets"""
        tcp_layer = packet[TCP]
        
        packet_info.update({
            'protocol': 'TCP',
            'src_port': tcp_layer.sport,
            'dst_port': tcp_layer.dport,
            'tcp_flags': self.get_tcp_flags(tcp_layer.flags),
            'seq_number': tcp_layer.seq,
            'ack_number': tcp_layer.ack,
            'window_size': tcp_layer.window
        })
        
        # Try to extract payload
        if packet[TCP].payload:
            payload = bytes(packet[TCP].payload)
            packet_info['payload_size'] = len(payload)
            # Only show first 50 bytes of payload for display
            packet_info['payload_preview'] = payload[:50].hex()
            
    def analyze_udp_packet(self, packet, packet_info):
        """Analyze UDP packets"""
        udp_layer = packet[UDP]
        
        packet_info.update({
            'protocol': 'UDP',
            'src_port': udp_layer.sport,
            'dst_port': udp_layer.dport,
            'udp_length': udp_layer.len,
            'checksum': udp_layer.chksum
        })
        
        # Try to extract payload
        if packet[UDP].payload:
            payload = bytes(packet[UDP].payload)
            packet_info['payload_size'] = len(payload)
            packet_info['payload_preview'] = payload[:50].hex()
            
    def analyze_icmp_packet(self, packet, packet_info):
        """Analyze ICMP packets"""
        icmp_layer = packet[ICMP]
        
        packet_info.update({
            'protocol': 'ICMP',
            'icmp_type': icmp_layer.type,
            'icmp_code': icmp_layer.code,
            'icmp_checksum': icmp_layer.chksum
        })
        
    def analyze_arp_packet(self, packet, packet_info):
        """Analyze ARP packets"""
        arp_layer = packet[ARP]
        
        packet_info.update({
            'protocol': 'ARP',
            'arp_operation': 'Request' if arp_layer.op == 1 else 'Reply',
            'src_mac': arp_layer.hwsrc,
            'dst_mac': arp_layer.hwdst,
            'src_ip': arp_layer.psrc,
            'dst_ip': arp_layer.pdst
        })
        
    def get_tcp_flags(self, flags):
        """Convert TCP flags to readable format"""
        flag_names = []
        if flags & 0x01: flag_names.append('FIN')
        if flags & 0x02: flag_names.append('SYN')
        if flags & 0x04: flag_names.append('RST')
        if flags & 0x08: flag_names.append('PSH')
        if flags & 0x10: flag_names.append('ACK')
        if flags & 0x20: flag_names.append('URG')
        return ','.join(flag_names) if flag_names else 'None'
        
    def display_packet_info(self, packet_info):
        """Display packet information in a formatted way"""
        print(f"\n{'='*60}")
        print(f"Packet #{packet_info['packet_number']} - {packet_info['timestamp']}")
        print(f"{'='*60}")
        print(f"Protocol: {packet_info.get('protocol', 'Unknown')}")
        print(f"Size: {packet_info['size']} bytes")
        
        if 'src_ip' in packet_info:
            print(f"Source IP: {packet_info['src_ip']}")
            print(f"Destination IP: {packet_info['dst_ip']}")
            
        if 'src_port' in packet_info:
            print(f"Source Port: {packet_info['src_port']}")
            print(f"Destination Port: {packet_info['dst_port']}")
            
        if packet_info.get('protocol') == 'TCP':
            print(f"TCP Flags: {packet_info.get('tcp_flags', 'None')}")
            print(f"Sequence Number: {packet_info.get('seq_number', 'N/A')}")
            
        if packet_info.get('protocol') == 'ARP':
            print(f"Operation: {packet_info.get('arp_operation', 'Unknown')}")
            print(f"Source MAC: {packet_info.get('src_mac', 'N/A')}")
            
        if 'payload_preview' in packet_info:
            print(f"Payload Size: {packet_info['payload_size']} bytes")
            print(f"Payload Preview: {packet_info['payload_preview']}...")
            
    def start_sniffing(self):
        """Start the packet capture process"""
        print(f"\n{'='*60}")
        print("🔍 CodeAlpha Network Sniffer Started")
        print(f"{'='*60}")
        print(f"Interface: {self.interface if self.interface else 'All interfaces'}")
        print(f"Count: {'Unlimited' if self.count == 0 else self.count}")
        print(f"Filter: {self.filter_protocol if self.filter_protocol else 'All protocols'}")
        print("Press Ctrl+C to stop sniffing...")
        print(f"{'='*60}")
        
        try:
            # Start packet capture
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                count=self.count,
                filter=self.filter_protocol,
                store=0  # Don't store packets in memory
            )
        except KeyboardInterrupt:
            print(f"\n\n{'='*60}")
            print("🛑 Sniffing stopped by user")
            print(f"Total packets captured: {self.packet_count}")
            print(f"{'='*60}")
            
        except Exception as e:
            print(f"\n❌ Error during packet capture: {e}")
            print("Make sure you're running with appropriate privileges (sudo)")
            
    def save_results(self, filename):
        """Save captured packet information to a file"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.captured_packets, f, indent=2)
            print(f"✅ Results saved to {filename}")
        except Exception as e:
            print(f"❌ Error saving results: {e}")

def main():
    """Main function to run the network sniffer"""
    parser = argparse.ArgumentParser(
        description="CodeAlpha Basic Network Sniffer - Cybersecurity Internship Project"
    )
    
    parser.add_argument(
        '-i', '--interface',
        help='Network interface to sniff on (e.g., eth0, wlan0)',
        default=None
    )
    
    parser.add_argument(
        '-c', '--count',
        type=int,
        help='Number of packets to capture (0 = unlimited)',
        default=10
    )
    
    parser.add_argument(
        '-f', '--filter',
        help='BPF filter expression (e.g., "tcp", "udp port 53", "host 8.8.8.8")',
        default=None
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output file to save results',
        default=None
    )
    
    args = parser.parse_args()
    
    # Create and start the sniffer
    sniffer = NetworkSniffer(
        interface=args.interface,
        count=args.count,
        filter_protocol=args.filter
    )
    
    # Start sniffing
    sniffer.start_sniffing()
    
    # Save results if output file specified
    if args.output:
        sniffer.save_results(args.output)

if __name__ == "__main__":
    main()