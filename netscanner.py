#!/usr/bin/env python3
"""
NetScanner - A simple network scanner similar to nmap
Features: IP discovery, port scanning, service detection
"""

import socket
import ipaddress
import argparse
import sys
import threading
from datetime import datetime
from queue import Queue
import struct
import time

class NetworkScanner:
    def __init__(self, target, ports=None, timeout=1, threads=100):
      
        self.target = target
        self.timeout = timeout
        self.threads = threads
        self.scan_results = {}
        self.lock = threading.Lock()
        
        if ports is None:
            self.ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
                         993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
        elif isinstance(ports, str):
            self.ports = self._parse_port_range(ports)
        else:
            self.ports = ports
    
    def _parse_port_range(self, port_string):
        ports = []
        for part in port_string.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        return ports
    
    def _get_ip_list(self):
        try:
            network = ipaddress.ip_network(self.target, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            return [self.target]
    
    def _ping_sweep(self, ip):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            for port in [80, 443, 22, 445]:
                try:
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        sock.close()
                        return True
                except:
                    pass
            sock.close()
            return False
        except:
            return False
    
    def _scan_port(self, ip, port, queue):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                
                banner = self._grab_banner(sock, port)
                
                with self.lock:
                    if ip not in self.scan_results:
                        self.scan_results[ip] = []
                    self.scan_results[ip].append({
                        'port': port,
                        'state': 'open',
                        'service': service,
                        'banner': banner
                    })
            
            sock.close()
        except Exception as e:
            pass
        finally:
            queue.task_done()
    
    def _grab_banner(self, sock, port):
        try:
            if port in [80, 8080, 8443]:
                sock.send(b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n')
            elif port in [21, 22, 25, 110, 143]:
                pass  
            else:
                sock.send(b'\r\n')
            
            sock.settimeout(0.5)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:100] if banner else None
        except:
            return None
    
    def scan(self):
        print(f"\n{'='*70}")
        print(f"NetScanner v1.0 - Network Scanner")
        print(f"{'='*70}")
        print(f"Target: {self.target}")
        print(f"Ports: {len(self.ports)} ports")
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}\n")
        
        ip_list = self._get_ip_list()
        
        if len(ip_list) > 1:
            print(f"Scanning {len(ip_list)} hosts...\n")
        
        for ip in ip_list:
            if len(ip_list) > 1:
                sys.stdout.write(f"\rChecking {ip}...")
                sys.stdout.flush()
                if not self._ping_sweep(ip):
                    continue
                print(f" Host is up!")
            
            print(f"\nScanning {ip}...")
            print(f"{'-'*70}")
            
            queue = Queue()
            
            for _ in range(min(self.threads, len(self.ports))):
                t = threading.Thread(target=self._worker, args=(ip, queue))
                t.daemon = True
                t.start()

            for port in self.ports:
                queue.put(port)
            
            queue.join()
            
            self._display_results(ip)
        
        print(f"\n{'='*70}")
        print(f"Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}\n")
    
    def _worker(self, ip, queue):
        while True:
            try:
                port = queue.get(block=False)
                self._scan_port(ip, port, queue)
            except:
                break
    
    def _display_results(self, ip):
        if ip in self.scan_results and self.scan_results[ip]:
            print(f"\nOpen ports on {ip}:")
            print(f"{'PORT':<10} {'STATE':<10} {'SERVICE':<20} {'BANNER':<30}")
            print(f"{'-'*70}")
            
            for result in sorted(self.scan_results[ip], key=lambda x: x['port']):
                banner = result['banner'][:30] if result['banner'] else ''
                print(f"{result['port']:<10} {result['state']:<10} "
                      f"{result['service']:<20} {banner:<30}")
        else:
            print(f"No open ports found on {ip}")


def main():
    parser = argparse.ArgumentParser(
        description='NetScanner - A simple network scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.1
  %(prog)s 192.168.1.0/24 -p 1-1000
  %(prog)s 10.0.0.1 -p 80,443,8080
  %(prog)s scanme.nmap.org -p 1-65535 -t 200
        """
    )
    
    parser.add_argument('target', help='Target IP address or CIDR range')
    parser.add_argument('-p', '--ports', 
                       help='Port range (e.g., 1-1000 or 80,443,8080)',
                       default=None)
    parser.add_argument('-t', '--threads', 
                       type=int,
                       default=100,
                       help='Number of threads (default: 100)')
    parser.add_argument('--timeout',
                       type=float,
                       default=1.0,
                       help='Socket timeout in seconds (default: 1.0)')
    
    args = parser.parse_args()
    
    try:
        scanner = NetworkScanner(
            target=args.target,
            ports=args.ports,
            timeout=args.timeout,
            threads=args.threads
        )
        scanner.scan()
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user!")
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()