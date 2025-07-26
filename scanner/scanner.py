# scanner/scanner.py
import nmap
import logging

logger = logging.getLogger(__name__)

class Scanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan_ip(self, ip):
        logger.info(f"Scanning IP: {ip}")
        try:
            result = self.nm.scan(ip, arguments='-sS -Pn')
            return result
        except Exception as e:
            logger.error(f"Scan failed for {ip}: {e}")
            return None

def scan_open_ports(self, ip):
    logger.info(f"Scanning ports on {ip}")
    try:
        self.nm.scan(ip, arguments='-sS -Pn -p 1-65535')
        ports = []
        for proto in self.nm[ip].all_protocols():
            lport = self.nm[ip][proto].keys()
            for port in lport:
                state = self.nm[ip][proto][port]['state']
                if state == 'open':
                    service = self.nm[ip][proto][port]['name']
                    ports.append((port, proto, service))
        return ports
    except Exception as e:
        logger.error(f"Port scan failed for {ip}: {e}")
        return []
