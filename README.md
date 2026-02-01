# network_scanner_python

# Simple TCP Scanner

A small Python-based TCP port scanner built for quick checks on local networks and lab environments.

This is intentionally minimal no OS detection, no service probing, no aggressive scanning.  
If you need fullscale scanning, tools like nmap already do that better.

## What This Does

- Scans a given subnet for open TCP ports
- Uses a configurable thread pool for speed
- Defaults to common ports (22, 80, 443)
- Outputs only hosts with open ports found

Built for readability and learning, not stealth or mass scanning.
