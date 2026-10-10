#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CVE-2026-94293 (AAS Edge Client) Unified Scanner & Hunter
This script created by Nabeel Hasan ===> NULL200OK
GitHub: https://github.com/NULL200OK

DISCLAIMER:
    This tool is intended for authorized security testing only.
    Use it only on systems you own or have explicit written permission to test.
    Unauthorized scanning is illegal and unethical.
"""

import argparse
import asyncio
import csv
import ipaddress
import json
import logging
import sys
import time
from dataclasses import dataclass, asdict, field
from typing import List, Optional

import aiohttp
from aiohttp import ClientTimeout, TCPConnector

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("aas_scanner")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class ScanResult:
    target: str
    port: int
    scheme: str
    url: str
    status_code: int
    content_type: str
    evidence: str
    timestamp: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------
class AASScanner:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.results: List[ScanResult] = []
        self.semaphore = asyncio.Semaphore(args.concurrency)
        self.timeout = ClientTimeout(total=args.timeout)
        self.headers = {"User-Agent": args.user_agent}
        self.verify_ssl = not args.insecure
        self.path = args.path
        self.schemes = args.schemes
        self.ports = args.ports
        self.rate_limit = args.rate_limit
        self.last_request_time = 0.0
        self.rate_lock = asyncio.Lock()

    async def _wait_rate_limit(self):
        """Simple global rate limiter."""
        if self.rate_limit <= 0:
            return
        async with self.rate_lock:
            now = time.monotonic()
            delay = 1.0 / self.rate_limit
            if now - self.last_request_time < delay:
                await asyncio.sleep(delay - (now - self.last_request_time))
            self.last_request_time = time.monotonic()

    def _analyze_response(self, text: str, content_type: str) -> Optional[str]:
        """Heuristic detection for exposed AAS submodel endpoint."""
        evidence_parts = []

        if "application/json" in content_type:
            evidence_parts.append("JSON content-type")
            try:
                data = json.loads(text)
                if isinstance(data, dict):
                    keys = set(data.keys())
                    if "submodels" in keys or "submodel" in keys:
                        evidence_parts.append("submodel key found")
                    elif "data" in keys and isinstance(data["data"], list):
                        evidence_parts.append("data list found")
                elif isinstance(data, list):
                    if any("submodel" in str(item).lower() for item in data[:5]):
                        evidence_parts.append("submodel in list")
            except json.JSONDecodeError:
                pass

        if "submodel" in text.lower():
            evidence_parts.append("submodel string in body")

        if evidence_parts:
            return "; ".join(evidence_parts)
        return None

    async def check_target(self, session: aiohttp.ClientSession, target: str, port: int):
        for scheme in self.schemes:
            url = f"{scheme}://{target}:{port}{self.path}"
            await self._wait_rate_limit()
            try:
                async with self.semaphore:
                    async with session.get(
                        url,
                        timeout=self.timeout,
                        allow_redirects=False,
                    ) as resp:
                        status = resp.status
                        content_type = resp.headers.get("Content-Type", "")
                        text = await resp.text()

                        if status == 200:
                            evidence = self._analyze_response(text, content_type)
                            if evidence:
                                result = ScanResult(
                                    target=target,
                                    port=port,
                                    scheme=scheme,
                                    url=url,
                                    status_code=status,
                                    content_type=content_type,
                                    evidence=evidence,
                                )
                                self.results.append(result)
                                logger.info(f"[VULNERABLE] {url} -> {evidence}")
                                return result
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                logger.debug(f"Error {url}: {exc}")
                continue
        return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def print_banner():
    banner = r"""
    ===============================================================
      CVE-2026-94293 (AAS Edge Client) Unified Scanner & Hunter
      This script created by Nabeel Hasan ===> NULL200OK
      GitHub: https://github.com/NULL200OK
    ===============================================================
    """
    print(banner)


def generate_targets(args: argparse.Namespace) -> List[str]:
    targets: List[str] = []
    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
    elif args.cidr:
        for cidr in args.cidr:
            network = ipaddress.ip_network(cidr, strict=False)
            targets.extend(str(ip) for ip in network.hosts())
    elif args.targets:
        targets.extend(args.targets)
    else:
        logger.error("No targets specified. Use --file, --cidr, or --targets.")
        sys.exit(1)

    seen = set()
    unique_targets = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique_targets.append(t)
    return unique_targets


def save_results(results: List[ScanResult], args: argparse.Namespace):
    if not results:
        logger.info("No vulnerable targets found.")
        return

    if args.output_txt:
        with open(args.output_txt, "w", encoding="utf-8") as f:
            for r in results:
                f.write(f"{r.url} | {r.evidence}\n")
        logger.info(f"TXT report saved: {args.output_txt}")

    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump([asdict(r) for r in results], f, indent=2, ensure_ascii=False)
        logger.info(f"JSON report saved: {args.output_json}")

    if args.output_csv:
        with open(args.output_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=asdict(results[0]).keys())
            writer.writeheader()
            for r in results:
                writer.writerow(asdict(r))
        logger.info(f"CSV report saved: {args.output_csv}")


async def run_scan(args: argparse.Namespace):
    targets = generate_targets(args)
    logger.info(f"Loaded {len(targets)} unique targets.")

    scanner = AASScanner(args)
    connector = TCPConnector(ssl=scanner.verify_ssl, limit=args.concurrency)

    async with aiohttp.ClientSession(
        connector=connector,
        headers=scanner.headers,
    ) as session:
        tasks = []
        for target in targets:
            for port in args.ports:
                tasks.append(scanner.check_target(session, target, port))

        total = len(tasks)
        logger.info(f"Starting scan: {total} requests across {len(targets)} targets.")

        for i, coro in enumerate(asyncio.as_completed(tasks), 1):
            await coro
            if i % 100 == 0 or i == total:
                logger.info(f"Progress: {i}/{total}")

    logger.info("Scan completed.")
    logger.info(f"Total exposed/vulnerable instances found: {len(scanner.results)}")
    save_results(scanner.results, args)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CVE-2026-94293 AAS Edge Client Scanner (Authorized testing only)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--file", help="File containing target IPs/hosts (one per line)")
    parser.add_argument("--cidr", nargs="+", help="CIDR subnet(s) to scan, e.g. 192.168.1.0/24")
    parser.add_argument("--targets", nargs="+", help="Target IPs/hosts")
    parser.add_argument("--ports", nargs="+", type=int,
                        default=[80, 443, 8080, 8443, 5000, 8090],
                        help="Ports to scan")
    parser.add_argument("--schemes", nargs="+", default=["http", "https"],
                        help="Schemes to try")
    parser.add_argument("--path", default="/api/v1/submodels",
                        help="Endpoint path to check")
    parser.add_argument("--timeout", type=float, default=3.0,
                        help="Request timeout in seconds")
    parser.add_argument("--concurrency", type=int, default=100,
                        help="Maximum concurrent requests")
    parser.add_argument("--rate-limit", type=float, default=0,
                        help="Max requests per second (0 = unlimited)")
    parser.add_argument("--user-agent",
                        default="Mozilla/5.0 (compatible; AAS-Scanner/1.0)",
                        help="Custom User-Agent")
    parser.add_argument("--insecure", action="store_true",
                        help="Disable TLS certificate verification")
    parser.add_argument("--output-txt", default="aas_vulnerability_report.txt",
                        help="TXT output file")
    parser.add_argument("--output-json", default="aas_vulnerability_report.json",
                        help="JSON output file")
    parser.add_argument("--output-csv", default="aas_vulnerability_report.csv",
                        help="CSV output file")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable debug logging")
    parser.add_argument("--authorized", action="store_true",
                        help="Confirm you have explicit authorization to scan the targets")
    return parser.parse_args()


def main():
    print_banner()
    args = parse_args()

    if not args.authorized:
        print("[-] You must confirm authorization with --authorized")
        print("[-] Example: python aas_scanner.py --targets 192.168.1.1 --authorized")
        sys.exit(1)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        asyncio.run(run_scan(args))
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()