#!/usr/bin/env python3
"""
NetPhantom - Modular Pentest Orchestration Framework
Author: github.com/yourusername
License: MIT
"""

import argparse
import sys
import asyncio
import json
import time
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich import box

from core.orchestrator import Orchestrator
from core.plugin_manager import PluginManager
from utils.logger import get_logger

console = Console()
logger = get_logger("netphantom")

BANNER = """
[bold red]
 ███╗   ██╗███████╗████████╗██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
 ██╔██╗ ██║█████╗     ██║   ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
 ██║╚██╗██║██╔══╝     ██║   ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
 ██║ ╚████║███████╗   ██║   ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
[/bold red]
[dim]  Modular Pentest Orchestration Framework  |  For authorized use only[/dim]
"""


def print_banner():
    console.print(BANNER)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="netphantom",
        description="NetPhantom - Modular Pentest Orchestration Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  netphantom scan -t 192.168.1.1 -p 1-1000
  netphantom recon -t example.com --dns --whois
  netphantom full -t 192.168.1.1 --output report.html
  netphantom list-modules
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Command")

    # scan
    scan_parser = subparsers.add_parser("scan", help="Port & service scanning")
    scan_parser.add_argument("-t", "--target", required=True, help="Target IP or hostname")
    scan_parser.add_argument("-p", "--ports", default="1-1024", help="Port range (default: 1-1024)")
    scan_parser.add_argument("--technique", choices=["syn", "fin", "xmas", "null", "connect"],
                             default="connect", help="Scan technique")
    scan_parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout")
    scan_parser.add_argument("--concurrency", type=int, default=500, help="Concurrent connections")
    scan_parser.add_argument("--banner", action="store_true", help="Grab service banners")
    scan_parser.add_argument("--os-detect", action="store_true", help="OS fingerprinting (TTL/TCP)")

    # recon
    recon_parser = subparsers.add_parser("recon", help="Passive & active reconnaissance")
    recon_parser.add_argument("-t", "--target", required=True, help="Target domain or IP")
    recon_parser.add_argument("--dns", action="store_true", help="DNS enumeration")
    recon_parser.add_argument("--whois", action="store_true", help="WHOIS lookup")
    recon_parser.add_argument("--subdomains", action="store_true", help="Subdomain brute-force")
    recon_parser.add_argument("--wordlist", default=None, help="Custom wordlist for subdomain scan")

    # full
    full_parser = subparsers.add_parser("full", help="Full pipeline: recon + scan + vuln check + report")
    full_parser.add_argument("-t", "--target", required=True, help="Target")
    full_parser.add_argument("--ports", default="1-1024")
    full_parser.add_argument("--output", default="report.html", help="Output report file")
    full_parser.add_argument("--format", choices=["html", "json", "txt"], default="html")
    full_parser.add_argument("--concurrency", type=int, default=300)

    # list-modules
    subparsers.add_parser("list-modules", help="List all available modules")

    # vuln
    vuln_parser = subparsers.add_parser("vuln", help="Vulnerability checking against open ports")
    vuln_parser.add_argument("-t", "--target", required=True)
    vuln_parser.add_argument("--services", nargs="+", help="Services to check (e.g. ssh ftp http)")

    return parser


async def run_scan(args):
    from modules.scanners.port_scanner import PortScanner
    from modules.scanners.banner_grabber import BannerGrabber
    from modules.scanners.os_fingerprint import OSFingerprinter

    scanner = PortScanner(
        target=args.target,
        port_range=args.ports,
        technique=args.technique,
        timeout=args.timeout,
        concurrency=args.concurrency,
    )

    console.print(f"\n[bold cyan][ SCAN ][/bold cyan] Target: [yellow]{args.target}[/yellow] | "
                  f"Ports: [yellow]{args.ports}[/yellow] | "
                  f"Technique: [yellow]{args.technique.upper()}[/yellow]\n")

    start = time.time()
    results = await scanner.run()
    elapsed = time.time() - start

    open_ports = [r for r in results if r["state"] == "open"]

    _print_port_table(open_ports)
    console.print(f"\n[dim]Scanned in {elapsed:.2f}s | {len(results)} ports checked | "
                  f"{len(open_ports)} open[/dim]")

    if args.banner and open_ports:
        console.print("\n[bold cyan][ BANNER GRAB ][/bold cyan]")
        grabber = BannerGrabber(args.target, timeout=args.timeout)
        for p in open_ports:
            banner = await grabber.grab(p["port"])
            if banner:
                console.print(f"  [green]{p['port']}/tcp[/green]  {banner[:80]}")

    if args.os_detect:
        console.print("\n[bold cyan][ OS FINGERPRINT ][/bold cyan]")
        fp = OSFingerprinter(args.target)
        os_guess = await fp.detect()
        console.print(f"  Guess: [yellow]{os_guess}[/yellow]")

    return open_ports


async def run_recon(args):
    from modules.recon.dns_enum import DNSEnumerator
    from modules.recon.whois_lookup import WhoisLookup
    from modules.recon.subdomain_brute import SubdomainBrute

    console.print(f"\n[bold cyan][ RECON ][/bold cyan] Target: [yellow]{args.target}[/yellow]\n")
    results = {}

    if args.whois:
        console.print("[bold]WHOIS[/bold]")
        wh = WhoisLookup(args.target)
        info = await wh.lookup()
        results["whois"] = info
        for k, v in info.items():
            console.print(f"  [dim]{k}:[/dim] {v}")

    if args.dns:
        console.print("\n[bold]DNS Records[/bold]")
        dns = DNSEnumerator(args.target)
        records = await dns.enumerate()
        results["dns"] = records
        for rtype, values in records.items():
            for v in values:
                console.print(f"  [green]{rtype:6}[/green]  {v}")

    if args.subdomains:
        console.print("\n[bold]Subdomain Brute-force[/bold]")
        wordlist = args.wordlist or str(Path(__file__).parent / "utils" / "wordlists" / "subdomains.txt")
        brute = SubdomainBrute(args.target, wordlist=wordlist)
        found = await brute.run()
        results["subdomains"] = found
        for sub in found:
            console.print(f"  [green]FOUND[/green]  {sub['subdomain']}  →  {sub['ip']}")

    return results


async def run_full(args):
    from modules.scanners.port_scanner import PortScanner
    from modules.scanners.banner_grabber import BannerGrabber
    from modules.recon.dns_enum import DNSEnumerator
    from modules.scanners.vuln_checker import VulnChecker
    from reports.report_gen import ReportGenerator

    orchestrator = Orchestrator(target=args.target)
    report_data = await orchestrator.run_full_pipeline(
        port_range=args.ports,
        concurrency=args.concurrency,
    )

    gen = ReportGenerator(report_data)
    outfile = gen.generate(fmt=args.format, path=args.output)
    console.print(f"\n[bold green][ REPORT ][/bold green] Saved to [yellow]{outfile}[/yellow]")


def list_modules():
    pm = PluginManager()
    modules = pm.list_all()

    table = Table(title="Available Modules", box=box.SIMPLE_HEAVY, style="dim")
    table.add_column("Name", style="bold cyan")
    table.add_column("Category", style="yellow")
    table.add_column("Description")

    for m in modules:
        table.add_row(m["name"], m["category"], m["description"])

    console.print(table)


def _print_port_table(ports):
    if not ports:
        console.print("  [dim]No open ports found.[/dim]")
        return

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    table.add_column("Port", style="green", width=10)
    table.add_column("State", width=8)
    table.add_column("Service", style="cyan")
    table.add_column("Version / Info")

    for p in ports:
        table.add_row(
            f"{p['port']}/tcp",
            p.get("state", "open"),
            p.get("service", "unknown"),
            p.get("version", ""),
        )
    console.print(table)


def main():
    print_banner()
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    try:
        if args.command == "scan":
            asyncio.run(run_scan(args))
        elif args.command == "recon":
            asyncio.run(run_recon(args))
        elif args.command == "full":
            asyncio.run(run_full(args))
        elif args.command == "list-modules":
            list_modules()
        elif args.command == "vuln":
            asyncio.run(run_vuln(args))
    except KeyboardInterrupt:
        console.print("\n[bold red]Interrupted.[/bold red]")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal: {e}", exc_info=True)
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
