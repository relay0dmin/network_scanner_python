#!/usr/bin/env python3

# Simple TCP scanner.
# Nothing fancy. Meant for quick checks.(got bored)
# If you need mass scanning, nmap already exists.

import socket
import ipaddress
import argparse
import logging
from concurrent.futures import ThreadPoolExecutor

DEFAULT_PORTS = [22, 80, 443]
TIMEOUT = 0.4


def port_open(host, port):
    # Using create_connection keeps this short and readable
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT):
            return True
    except OSError:
        return False


def scan_host(host, ports):
    open_ports = []

    for p in ports:
        if port_open(host, p):
            open_ports.append(p)

    return open_ports


def expand_hosts(subnet):
    # strict=False allows things like /24 without network math errors
    net = ipaddress.ip_network(subnet, strict=False)
    for h in net.hosts():
        yield str(h)


def run_scan(subnet, ports, workers):
    results = {}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = []

        for host in expand_hosts(subnet):
            futures.append(
                pool.submit(scan_host, host, ports)
            )

        for host, future in zip(expand_hosts(subnet), futures):
            ports_found = future.result()
            if ports_found:
                results[host] = ports_found

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Small Python TCP scanner (educational use)"
    )
    parser.add_argument("subnet", help="Target subnet (ex: 192.168.1.0/24)")
    parser.add_argument(
        "-p", "--ports",
        help="Comma-separated ports (default: 22,80,443)",
        default="22,80,443"
    )
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=64,
        help="Thread count (default: 64)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug output"
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s"
    )

    try:
        ipaddress.ip_network(args.subnet, strict=False)
    except ValueError:
        logging.error("Invalid subnet format.")
        return

    try:
        ports = [int(p.strip()) for p in args.ports.split(",")]
    except ValueError:
        logging.error("Invalid port list.")
        return

    logging.info(f"Scanning {args.subnet} on ports {ports}...\n")

    results = run_scan(args.subnet, ports, args.workers)

    if not results:
        logging.info("No open ports found.")
        return

    for host, open_ports in results.items():
        logging.info(f"{host:<15} open -> {', '.join(map(str, open_ports))}")

    # TODO: banner grabbing could go here if needed


if __name__ == "__main__":
    main()
