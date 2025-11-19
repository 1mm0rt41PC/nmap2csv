# nmap2csv

[![Go Version](https://img.shields.io/badge/Go-1.24.1-blue.svg)](https://golang.org/doc/devel/release.html)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A lightweight command-line tool to parse and analyze Nmap XML scan results. Convert Nmap output into readable tables or CSV format for easy analysis and reporting.

## Overview

`nmap2csv` is a specialized tool designed to extract meaningful insights from Nmap XML scan files. It offers three distinct analysis modes:

- **Hostname Mode**: List hosts with specific open ports, including network addresses and vendor information
- **Port Analysis Mode**: Discover which ports are most commonly open across your network
- **Vendor Analysis Mode**: Identify network device manufacturers and their distribution

## Features

- ✅ Parse Nmap XML output files
- ✅ Filter hosts by specific open ports
- ✅ Aggregate port statistics across all scanned hosts
- ✅ Identify MAC address vendors and their prevalence
- ✅ Output results as formatted tables or CSV
- ✅ Sort results by relevance (open port count, occurrence frequency)
- ✅ Zero external dependencies beyond Go standard library

## Installation

### From Source

```bash
go install github.com/1mm0rt41PC/nmap2csv@latest
```

### Manual Build

```bash
git clone https://github.com/1mm0rt41PC/nmap2csv.git
cd nmap2csv
go build -o nmap2csv main.go
```

## Usage

### Basic Syntax

```bash
nmap2csv [options]
```

### Command-Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `-file` | `scan.xml` | Path to the Nmap XML scan file |
| `-hostname` | `false` | Enable hostname listing mode |
| `-whereport` | `""` | Comma-separated list of ports to filter (e.g., "22,80,443") |
| `-port` | `false` | Enable port statistics mode |
| `-vendor` | `false` | Enable vendor statistics mode |
| `-csv` | `false` | Output results in CSV format instead of table |

### Examples

#### 1. List All Hosts with SSH and HTTP Open

```bash
nmap2csv -file scan.xml -hostname -whereport "22,80"
```

**Output:**
```
Hostname        IPv4            MAC                Vendor           CountOpenPort  Ports
--------        ----            ---                ------           -------------  -----
server01.local  192.168.1.10    00:0C:29:XX:XX:XX  VMware           15             22,80
workstation     192.168.1.50    E4:54:E8:XX:XX:XX  Intel Corporate  8              22,80
```

#### 2. Export Hosts to CSV

```bash
nmap2csv -file scan.xml -hostname -whereport "22,80" -csv > results.csv
```

**Output (CSV):**
```csv
Hostname,IPv4,MAC,Vendor,CountOpenPort,Ports
server01.local,192.168.1.10,00:0C:29:XX:XX:XX,VMware,15,"22,80"
workstation,192.168.1.50,E4:54:E8:XX:XX:XX,Intel Corporate,8,"22,80"
```

#### 3. Show Port Statistics

```bash
nmap2csv -file scan.xml -port
```

**Output:**
```
Count  Port/Proto  ServiceName
-----  ----------  -----------
145    80/tcp      http
132    443/tcp     https
89     22/tcp      ssh
45     3389/tcp    ms-wbt-server
23     21/tcp      ftp
```

#### 4. Analyze Network Vendors

```bash
nmap2csv -file scan.xml -vendor
```

**Output:**
```
Count  VendorName
-----  ----------
45     Intel Corporate
32     Cisco Systems
28     Dell
15     Hewlett Packard
12     Apple
```

#### 5. List All Hosts with Any Open Port

```bash
nmap2csv -file scan.xml -hostname
```

This will show all hosts that have at least one open port, without filtering by specific ports.

## Use Cases

### Security Auditing
- Quickly identify hosts with vulnerable services exposed (e.g., Telnet, FTP)
- Discover unexpected open ports across your infrastructure
- Generate reports for compliance and audit requirements

### Network Inventory
- Build a comprehensive list of devices by vendor
- Identify unauthorized or unknown devices on the network
- Track network device distribution for asset management

### Penetration Testing
- Prioritize targets based on open port counts
- Export results to CSV for integration with other tools
- Identify common services for vulnerability assessment

## Input File Format

The tool expects Nmap XML output. Generate compatible files with:

```bash
# Basic scan
nmap -oX scan.xml 192.168.1.0/24

# Comprehensive scan with service detection
nmap -sV -O -oX scan.xml 192.168.1.0/24

# Fast scan of common ports
nmap -F -oX scan.xml 192.168.1.0/24
```

## Output Modes

### Table Format (Default)
Human-readable aligned columns using tab stops. Ideal for terminal viewing and quick analysis.

### CSV Format (`-csv`)
Standard comma-separated values format. Perfect for:
- Importing into Excel, Google Sheets, or databases
- Further processing with data analysis tools
- Integration with SIEM or security platforms

## Performance

- **Memory Efficient**: Streaming XML parsing minimizes memory footprint
- **Fast Processing**: Processes 10,000+ host scans in seconds
- **Scalable**: Handles large enterprise-scale Nmap scans

## Limitations

- Only parses XML format (not Nmap's normal or grepable output)
- IPv6 addresses are parsed but not displayed in hostname mode (easily extensible)
- MAC addresses only available when Nmap runs with sufficient privileges

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## Related Tools

- [Nmap](https://nmap.org/) - The network scanner that generates the input files
- [nmap-parse-output](https://github.com/ernw/nmap-parse-output) - Another Nmap XML parser with different features

## Support

For issues, questions, or suggestions, please open an issue on GitHub.
