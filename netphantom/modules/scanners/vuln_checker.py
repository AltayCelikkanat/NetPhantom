"""
modules/scanners/vuln_checker.py
Matches open port banners against a local CVE/vuln signature database.
"""
import re
from typing import List, Dict
from utils.logger import get_logger
logger = get_logger("vuln_checker")

# Signature format: (regex_on_banner, cve, severity, description, recommendation)
SIGNATURES = [
    # SSH
    (r"OpenSSH[_ ]([34]\.|5\.[0-8])", "CVE-2016-0777", "HIGH",
     "OpenSSH <7.1: UseRoaming memory leak (credential exposure)",
     "Upgrade to OpenSSH 7.1+"),
    (r"OpenSSH[_ ](2\.|3\.|4\.[0-3])", "CVE-2008-5161", "MEDIUM",
     "OpenSSH CBC mode IV reuse vulnerability",
     "Upgrade OpenSSH and disable CBC ciphers"),

    # FTP
    (r"vsFTPd 2\.3\.4", "CVE-2011-2523", "CRITICAL",
     "vsFTPd 2.3.4 backdoor — remote shell on port 6200",
     "Replace vsFTPd immediately"),
    (r"ProFTPD 1\.(2|3\.[0-2])", "CVE-2010-4221", "HIGH",
     "ProFTPD TELNET_IAC buffer overflow (pre-auth RCE)",
     "Upgrade to ProFTPD 1.3.3+"),

    # HTTP
    (r"Apache[/ ]2\.[0-3]\.", "CVE-2017-7679", "HIGH",
     "Apache <2.4.26: mod_mime buffer overread",
     "Upgrade Apache to 2.4.26+"),
    (r"Apache[/ ]2\.4\.(0|[1-9]|1[0-9]|2[0-8])\b", "CVE-2021-41773", "CRITICAL",
     "Apache 2.4.49 path traversal & RCE",
     "Patch to Apache 2.4.51+"),
    (r"nginx/1\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16)\.", "CVE-2019-9511", "MEDIUM",
     "nginx HTTP/2 DoS vulnerability",
     "Upgrade nginx to 1.17.3+"),
    (r"IIS/[45678]\.", "CVE-2017-7269", "CRITICAL",
     "IIS 6.0 WebDAV buffer overflow (pre-auth RCE)",
     "Disable WebDAV or upgrade IIS"),

    # MySQL
    (r"mysql.*5\.[0-6]\.", "CVE-2016-6662", "CRITICAL",
     "MySQL <5.7.15 remote root exploit via my.cnf injection",
     "Upgrade MySQL to 5.7.15+"),

    # Redis
    (r"Redis", "CVE-2022-0543", "CRITICAL",
     "Redis Lua sandbox escape (unauthenticated RCE possible if exposed)",
     "Bind Redis to localhost; add requirepass"),

    # Telnet
    (r".*", "INFO-001", "HIGH",
     "Telnet service detected — plaintext credential transmission",
     "Disable Telnet; use SSH"),

    # SMB (banner-less, port-based)
    (r".*", "CVE-2017-0144", "CRITICAL",
     "Port 445 open — potential EternalBlue/MS17-010 exposure",
     "Apply MS17-010 patch; disable SMBv1"),
]

PORT_SIGS = {
    23:   [("INFO-TELNET", "HIGH",  "Telnet service open",              "Replace with SSH")],
    445:  [("CVE-2017-0144", "CRITICAL", "SMB exposed — check MS17-010", "Patch + disable SMBv1")],
    3389: [("CVE-2019-0708", "CRITICAL", "RDP exposed — BlueKeep risk",  "Apply KB4499175; NLA mandatory")],
    6379: [("INFO-REDIS",    "HIGH",  "Redis port open without auth check", "Bind to 127.0.0.1")],
    27017:[("INFO-MONGO",    "HIGH",  "MongoDB port open — check auth",  "Enable --auth")],
}


class VulnChecker:
    def check(self, port_info: Dict) -> List[Dict]:
        port    = port_info.get("port", 0)
        banner  = port_info.get("banner", "") or ""
        service = port_info.get("service", "")
        results = []

        # Banner-based matching
        for pattern, cve, severity, desc, rec in SIGNATURES:
            if re.search(pattern, banner, re.IGNORECASE):
                results.append(self._make(port, cve, severity, desc, rec, banner[:80]))

        # Port-based matching (no banner needed)
        if port in PORT_SIGS and not banner:
            for cve, severity, desc, rec in PORT_SIGS[port]:
                results.append(self._make(port, cve, severity, desc, rec, ""))

        return results

    def _make(self, port, cve, severity, desc, rec, evidence) -> Dict:
        return {
            "port":           port,
            "cve":            cve,
            "severity":       severity,
            "description":    desc,
            "recommendation": rec,
            "evidence":       evidence,
        }
