"""
core/plugin_manager.py
Dynamically loads and registers scanner/exploit/recon modules.
"""

import importlib
import pkgutil
from pathlib import Path
from typing import List, Dict
from utils.logger import get_logger

logger = get_logger("plugin_manager")

BUILTIN_MODULES = [
    {"name": "port_scanner",     "category": "scanner",  "description": "Raw async TCP port scanner (SYN/FIN/XMAS/CONNECT)"},
    {"name": "banner_grabber",   "category": "scanner",  "description": "Service banner grabbing over raw sockets"},
    {"name": "os_fingerprint",   "category": "scanner",  "description": "TTL & TCP stack OS fingerprinting"},
    {"name": "vuln_checker",     "category": "scanner",  "description": "CVE/banner-based vulnerability matching"},
    {"name": "dns_enum",         "category": "recon",    "description": "DNS A/MX/NS/TXT/AAAA record enumeration"},
    {"name": "whois_lookup",     "category": "recon",    "description": "WHOIS domain registration data"},
    {"name": "subdomain_brute",  "category": "recon",    "description": "Async subdomain brute-force with wordlist"},
    {"name": "report_gen",       "category": "report",   "description": "HTML / JSON / TXT report generator"},
]


class PluginManager:
    def __init__(self):
        self._modules = {}

    def list_all(self) -> List[Dict]:
        return BUILTIN_MODULES

    def load(self, category: str, name: str):
        key = f"{category}.{name}"
        if key in self._modules:
            return self._modules[key]
        try:
            mod = importlib.import_module(f"modules.{category}.{name}")
            self._modules[key] = mod
            return mod
        except ImportError as e:
            logger.error(f"Failed to load module {key}: {e}")
            raise
