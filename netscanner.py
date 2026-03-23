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
from queue import Queue, Empty
import ssl
import json
import re
import random

class NetworkScanner:
    DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                     993, 995, 1723, 3306, 3389, 5900, 8080, 8443]

    # A slightly broader set commonly seen in CTF infrastructure (still TCP connect scan).
    CTF_PORTS = sorted(set(DEFAULT_PORTS + [
        53, 80, 81, 82, 83, 88, 90, 101, 110, 111, 123, 135, 137, 138, 139,
        143, 389, 443, 445, 465, 587, 591, 631, 636, 873, 902, 989, 990, 993, 995,
        1433, 1521, 2049, 2121, 2375, 2376, 2600, 27017, 27018, 27019, 2888, 3000,
        3128, 3306, 3389, 4369, 4443, 4500, 5000, 5001, 5002, 5432, 5601, 5672,
        5800, 5900, 6379, 7001, 8000, 8001, 8008, 8080, 8081, 8089, 8181, 8222, 8321,
        8888, 9000, 9001, 9042, 9090, 9200, 11211, 1337, 31337, 5984, 5985, 5986, 8003
    ]))

    def __init__(
        self,
        target,
        ports=None,
        timeout=1,
        threads=100,
        preset="default",
        host_up_check=True,
        host_up_ports=None,
        http_method="HEAD",
        http_path="/",
        tls_banners=False,
        max_banner_bytes=2048,
        read_timeout=0.75,
        retries=0,
        no_banner=False,
        max_hosts=None,
        shuffle_targets=False,
        smtp_ehlo=True,
        verbose=False,
    ):
        self.target = target
        self.timeout = timeout
        self.threads = threads
        self.preset = preset
        self.host_up_check = host_up_check
        self.host_up_ports = host_up_ports or [80, 443, 22, 445]
        self.http_method = http_method.upper().strip()
        self.http_path = http_path if http_path else "/"
        self.tls_banners = tls_banners
        self.max_banner_bytes = max_banner_bytes
        self.read_timeout = read_timeout
        self.retries = max(0, int(retries))
        self.no_banner = no_banner
        self.max_hosts = max_hosts
        self.shuffle_targets = shuffle_targets
        self.smtp_ehlo = smtp_ehlo
        self.verbose = verbose
        self.scan_results = {}
        self.lock = threading.Lock()
        
        if ports is None:
            if self.preset == "ctf":
                self.ports = list(self.CTF_PORTS)
            else:
                self.ports = list(self.DEFAULT_PORTS)
        elif isinstance(ports, str):
            self.ports = self._parse_port_range(ports)
        else:
            self.ports = ports

        # Deduplicate and validate
        self.ports = sorted(set(int(p) for p in self.ports if self._is_valid_port(p)))
        if not self.ports:
            raise ValueError("No valid ports to scan.")
    
    def _is_valid_port(self, port):
        try:
            port = int(port)
        except (TypeError, ValueError):
            return False
        return 1 <= port <= 65535

    def _parse_port_range(self, port_string):
        ports = []
        for part in port_string.split(','):
            part = part.strip()
            if not part:
                continue
            if '-' in part:
                start, end = map(int, part.split('-'))
                if start > end:
                    start, end = end, start
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        # Validate and deduplicate
        return sorted(set(p for p in ports if self._is_valid_port(p)))
    
    def _get_ip_list(self):
        try:
            network = ipaddress.ip_network(self.target, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            # Allow hostnames; expand to all A/AAAA targets if possible.
            try:
                infos = socket.getaddrinfo(self.target, None, proto=socket.IPPROTO_TCP)
                ips = set()
                for info in infos:
                    sockaddr = info[4]
                    if isinstance(sockaddr, tuple) and sockaddr:
                        ips.add(sockaddr[0])
                return sorted(ips) if ips else [self.target]
            except socket.gaierror:
                return [self.target]
    
    def _ping_sweep(self, ip):
        # TCP "is host up?" heuristic: try a small set of ports.
        for port in self.host_up_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    if sock.connect_ex((ip, port)) == 0:
                        return True
            except OSError:
                continue
        return False
    
    def _scan_port(self, ip, port, queue):
        try:
            # Retry helps on flaky services and in CTF environments with jitter.
            for _ in range(self.retries + 1):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(self.timeout)
                        result = sock.connect_ex((ip, port))
                        if result != 0:
                            continue

                        try:
                            service = socket.getservbyport(port)
                        except OSError:
                            service = "unknown"

                        banner = None if self.no_banner else self._grab_banner(ip, port, sock)

                        with self.lock:
                            if ip not in self.scan_results:
                                self.scan_results[ip] = []
                            self.scan_results[ip].append({
                                "port": port,
                                "state": "open",
                                "service": service,
                                "banner": banner,
                            })
                        break
                except OSError:
                    continue
        except Exception:
            # Keep scanning; failures are expected on some ports/hosts.
            pass
        finally:
            queue.task_done()
    
    def _wrap_tls(self, sock, server_name):
        # For scanning/banners we generally don't want to fail on cert trust.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx.wrap_socket(sock, server_hostname=server_name)

    def _read_some(self, sock, max_bytes=None):
        max_bytes = max_bytes or self.max_banner_bytes
        try:
            sock.settimeout(self.read_timeout)
            data = sock.recv(max_bytes)
            if not data:
                return None
            text = data.decode("utf-8", errors="ignore").strip()
            return text[:200] if text else None
        except (socket.timeout, OSError):
            return None

    def _recv_until_timeout(self, sock, limit_bytes=4096):
        """Best-effort read of whatever the server sends right now."""
        chunks = []
        total = 0
        while total < limit_bytes:
            try:
                sock.settimeout(self.read_timeout)
                part = sock.recv(1024)
                if not part:
                    break
                chunks.append(part)
                total += len(part)
                # If we're getting small chunks, stop early to avoid delaying scans.
                if len(part) < 1024:
                    break
            except (socket.timeout, OSError):
                break
        raw = b"".join(chunks)
        if not raw:
            return None
        text = raw.decode("utf-8", errors="ignore").strip()
        return text[:400] if text else None

    def _tls_cert_summary(self, tls_sock):
        if not tls_sock:
            return ""
        try:
            cert = tls_sock.getpeercert()
        except Exception:
            return ""

        cn = ""
        issuer = ""
        not_after = ""

        def _iter_kv_pairs(obj):
            """
            Walk the structure returned by getpeercert() and yield (key, value) pairs.
            Handles typical layouts like ((('commonName','example.com'),),).
            """
            if obj is None:
                return
            if isinstance(obj, dict):
                for k, v in obj.items():
                    yield str(k), v
                return
            if isinstance(obj, (list, tuple)):
                # Direct (key, value) pair
                if len(obj) == 2 and isinstance(obj[0], str):
                    yield obj[0], obj[1]
                    return
                for item in obj:
                    yield from _iter_kv_pairs(item)
                return

        try:
            for k, v in _iter_kv_pairs(cert.get("subject")):
                if str(k).lower() == "commonname":
                    cn = str(v)
                    break
        except Exception:
            pass

        try:
            for k, v in _iter_kv_pairs(cert.get("issuer")):
                if str(k).lower() == "organization" and not issuer:
                    issuer = str(v)
        except Exception:
            pass

        try:
            not_after = cert.get("notAfter", "")
        except Exception:
            pass

        parts = []
        if cn:
            parts.append(f"CN={cn}")
        if issuer:
            parts.append(f"IssuerOrg={issuer}")
        if not_after:
            parts.append(f"ValidTo={not_after}")
        return " | ".join(parts)

    def _http_banner(self, ip, sock, port, method="HEAD", path="/"):
        method = method.upper()
        host = str(ip)
        req = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: NetScanner/1.1\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("ascii", errors="ignore")

        try:
            sock.settimeout(self.read_timeout)
            sock.send(req)
        except OSError:
            return None

        # Read a small amount of response to extract server/status/title.
        chunks = []
        total = 0
        try:
            while total < min(self.max_banner_bytes, 4096):
                part = sock.recv(1024)
                if not part:
                    break
                chunks.append(part)
                total += len(part)
        except (socket.timeout, OSError):
            pass

        raw = b"".join(chunks)
        if not raw:
            return None

        text = raw.decode("utf-8", errors="ignore")
        # Status line is usually first line.
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        status = lines[0] if lines else ""
        server = ""
        m = re.search(r"^server:\s*(.+)$", text, flags=re.IGNORECASE | re.MULTILINE)
        if m:
            server = m.group(1).strip()
        title = ""
        tm = re.search(r"<title[^>]*>(.*?)</title>", text, flags=re.IGNORECASE | re.DOTALL)
        if tm:
            title = " ".join(tm.group(1).strip().split())[:80]

        parts = [p for p in [status, f"Server={server}" if server else "", f"Title={title}" if title else ""] if p]
        banner = " | ".join(parts)
        return banner[:200] if banner else None

    def _smtp_banner(self, sock):
        # SMTP is line-based; do best-effort greeting + optional EHLO.
        greeting = self._recv_until_timeout(sock, limit_bytes=1024)
        if not self.smtp_ehlo:
            return greeting

        try:
            sock.send(b"EHLO netscanner\r\n")
        except OSError:
            return greeting

        resp = self._recv_until_timeout(sock, limit_bytes=2048)
        if not resp:
            return greeting
        # Keep it short and CTF-friendly.
        joined = greeting or ""
        if joined and resp:
            joined = f"{joined} | {resp}"
        else:
            joined = resp
        return joined[:300] if joined else None

    def _grab_banner(self, ip, port, sock):
        # HTTP/HTTPS probing for web-friendly ports.
        if port in (80, 8080, 8000, 8008, 8001) and sock:
            return self._http_banner(ip, sock, port, method=self.http_method, path=self.http_path)

        if port in (443, 8443) and self.tls_banners and sock:
            try:
                tls_sock = self._wrap_tls(sock, server_name=str(ip))
                try:
                    http = self._http_banner(ip, tls_sock, port, method=self.http_method, path=self.http_path)
                    tls_info = self._tls_cert_summary(tls_sock)
                    if http and tls_info:
                        return f"{http} | {tls_info}"[:300]
                    return (http or tls_info)[:300] if (http or tls_info) else None
                finally:
                    try:
                        tls_sock.close()
                    except OSError:
                        pass
            except ssl.SSLError:
                return None

        # TLS-only greeting ports (POP3S/IMAPS) if enabled.
        if port in (993, 995) and self.tls_banners and sock:
            try:
                with self._wrap_tls(sock, server_name=str(ip)) as tls_sock:
                    greeter = self._read_some(tls_sock) or self._recv_until_timeout(tls_sock)
                    tls_info = self._tls_cert_summary(tls_sock)
                    if greeter and tls_info:
                        return f"{greeter} | {tls_info}"[:300]
                    return (greeter or tls_info)[:300] if (greeter or tls_info) else None
            except ssl.SSLError:
                return None

        # Non-HTTP services: attempt to read a banner without sending.
        if port in (25, 587):
            try:
                return self._smtp_banner(sock)
            except Exception:
                pass

        if port in (21, 22, 23, 25, 110, 143, 465, 587):
            return self._read_some(sock)

        # Fallback: best-effort read.
        return self._read_some(sock)
    
    def scan(self):
        print(f"\n{'='*70}")
        print(f"NetScanner v1.2 - Network Scanner")
        print(f"{'='*70}")
        print(f"Target: {self.target}")
        print(f"Ports: {len(self.ports)} ports")
        if self.host_up_check:
            print(f"Host-up check: tcp:{','.join(str(p) for p in self.host_up_ports)}")
        else:
            print("Host-up check: disabled")
        if self.tls_banners:
            print("TLS banners: enabled")
        if self.no_banner:
            print("Banner grabbing: disabled")
        if self.retries:
            print(f"Retries per port: {self.retries}")
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}\n")
        
        ip_list = self._get_ip_list()

        if self.shuffle_targets:
            random.shuffle(ip_list)

        if self.max_hosts is not None:
            ip_list = ip_list[: self.max_hosts]
        
        if len(ip_list) > 1:
            print(f"Scanning {len(ip_list)} hosts...\n")
        
        for ip in ip_list:
            if len(ip_list) > 1:
                sys.stdout.write(f"\rChecking {ip}...")
                sys.stdout.flush()
                if self.host_up_check and not self._ping_sweep(ip):
                    continue
                if self.host_up_check:
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
            except Empty:
                break
            except Exception:
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
    parser.add_argument('--preset',
                        choices=["default", "ctf"],
                        default="default",
                        help='Port preset to use when -p is not provided')
    parser.add_argument('--http-path',
                        default="/",
                        help='HTTP request path for web banner grabbing (default: /)')
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
    parser.add_argument('--retries',
                        type=int,
                        default=0,
                        help='Retries per open-port connection attempt (default: 0)')
    parser.add_argument('--no-banner',
                        action='store_true',
                        help='Disable banner grabbing (faster, less info)')
    parser.add_argument('--no-host-check',
                        action='store_true',
                        help='Disable TCP-based host discovery (scans all resolved hosts)')
    parser.add_argument('--max-hosts',
                        type=int,
                        default=0,
                        help='Stop after scanning N hosts (0 = no limit)')
    parser.add_argument('--shuffle-hosts',
                        action='store_true',
                        help='Randomize host processing order')
    parser.add_argument('--http-method',
                        choices=["HEAD", "GET"],
                        default="HEAD",
                        help='HTTP probing method for web services')
    parser.add_argument('--tls-banners',
                        action='store_true',
                        help='Enable TLS handshakes for HTTPS/IMAPS/POP3S banner grabbing')
    parser.add_argument('--no-smtp-ehlo',
                        action='store_true',
                        help='Do not send EHLO during SMTP banner grabbing')
    parser.add_argument('--max-banner-bytes',
                        type=int,
                        default=2048,
                        help='Maximum bytes to read for banner grabbing')
    parser.add_argument('--read-timeout',
                        type=float,
                        default=0.75,
                        help='Timeout (seconds) for banner reads')
    parser.add_argument('--json-out',
                        default=None,
                        help='If set, write scan results to this JSON file')
    parser.add_argument('--verbose',
                        action='store_true',
                        help='Enable verbose output')
    
    args = parser.parse_args()
    
    try:
        max_hosts = args.max_hosts if args.max_hosts and args.max_hosts > 0 else None
        scanner = NetworkScanner(
            target=args.target,
            ports=args.ports,
            timeout=args.timeout,
            threads=args.threads,
            preset=args.preset,
            host_up_check=not args.no_host_check,
            http_method=args.http_method,
            http_path=args.http_path,
            tls_banners=args.tls_banners,
            max_banner_bytes=args.max_banner_bytes,
            read_timeout=args.read_timeout,
            retries=args.retries,
            no_banner=args.no_banner,
            max_hosts=max_hosts,
            shuffle_targets=args.shuffle_hosts,
            smtp_ehlo=not args.no_smtp_ehlo,
            verbose=args.verbose,
        )
        scanner.scan()
        if args.json_out:
            payload = {
                "target": scanner.target,
                "ports": scanner.ports,
                "scan_results": scanner.scan_results,
            }
            with open(args.json_out, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user!")
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()