package main

import (
	"encoding/csv"
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
)

// ************************************************************************************************
// NmapRun represents the root structure of an Nmap XML scan output.
// It contains a collection of all scanned hosts with their associated information.
type NmapRun struct {
	Hosts []Host `xml:"host"`
}

// ************************************************************************************************
// Host represents a single scanned host in the Nmap output.
// It contains network addresses, hostnames, and open ports discovered during the scan.
type Host struct {
	Addresses []Address  `xml:"address"`
	Hostnames []Hostname `xml:"hostnames>hostname"`
	Ports     []Port     `xml:"ports>port"`
}

// ************************************************************************************************
// Address represents a network address associated with a host.
// This can be an IPv4, IPv6, or MAC address with optional vendor information.
type Address struct {
	// Addr is the actual address value (IP or MAC).
	Addr string `xml:"addr,attr"`

	// AddrType indicates the type of address (ipv4, ipv6, mac).
	AddrType string `xml:"addrtype,attr"`

	// Vendor is the manufacturer name for MAC addresses (empty for IP addresses).
	Vendor string `xml:"vendor,attr"`
}

// ************************************************************************************************
// Hostname represents a DNS hostname associated with a host.
type Hostname struct {
	// Name is the resolved hostname.
	Name string `xml:"name,attr"`
}

// ************************************************************************************************
// Port represents a single port on a scanned host.
// It includes the port number, protocol, state, and service information.
type Port struct {
	// Protocol is the transport protocol (tcp, udp, sctp).
	Protocol string `xml:"protocol,attr"`

	// PortID is the port number (0-65535).
	PortID int `xml:"portid,attr"`

	// State contains the current state of the port (open, closed, filtered).
	State State `xml:"state"`

	// Service contains information about the service running on this port.
	Service Service `xml:"service"`
}

// ************************************************************************************************
// State represents the current state of a port.
type State struct {
	// State indicates whether the port is open, closed, or filtered.
	State string `xml:"state,attr"`
}

// ************************************************************************************************
// Service represents a network service detected on a port.
type Service struct {
	// Name is the service name (http, ssh, ftp, etc.).
	Name string `xml:"name,attr"`
}

// ************************************************************************************************
// HostInfo holds aggregated information about a single host for display in hostname mode.
// This structure combines data from multiple sources (addresses, hostnames, ports) into
// a single record that can be easily sorted and displayed in table or CSV format.
type HostInfo struct {
	// Hostname is the resolved DNS hostname for this host (first hostname if multiple exist).
	Hostname string

	// IPv4 is the IPv4 address of the host.
	IPv4 string

	// MAC is the MAC address of the host's network interface.
	MAC string

	// Vendor is the NIC manufacturer name associated with the MAC address.
	Vendor string

	// CountOpen is the total number of open ports detected on this host.
	CountOpen int

	// Ports is a comma-separated list of matching open port numbers that meet the filter criteria.
	Ports string
}

// ************************************************************************************************
// PortInfo holds aggregated information about a port/protocol combination across all scanned hosts.
// This structure is used in port analysis mode to show which ports are most commonly open
// in the network, along with their associated service names.
type PortInfo struct {
	// Key is the port number and protocol combination in the format "portnum/protocol" (e.g., "80/tcp", "53/udp").
	Key string

	// Service is the detected service name for this port (e.g., "http", "ssh", "dns").
	Service string

	// Count is the number of hosts that have this port open in the scan results.
	Count int
}

// ************************************************************************************************
// VendorInfo holds aggregated information about a network interface card vendor.
// This structure is used in vendor analysis mode to identify the distribution of
// hardware manufacturers across the scanned network.
type VendorInfo struct {
	// Name is the vendor or manufacturer name (e.g., "Intel Corporate", "Cisco Systems").
	Name string

	// Count is the number of devices from this vendor found in the scan results.
	Count int
}

// ************************************************************************************************
// main is the entry point of the nmap2csv tool.
// It parses command-line flags and processes Nmap XML output in three modes:
//   - Hostname mode: Lists hosts with specific open ports
//   - Port mode: Shows unique ports with occurrence counts
//   - Vendor mode: Lists MAC address vendors with counts
//
// The output can be formatted as a table or CSV depending on the -csv flag.
func main() {
	xmlFile := flag.String("file", "scan.xml", "Nmap XML file")
	wherePorts := flag.String("whereport", "", "Comma-separated list of ports")
	showHostnames := flag.Bool("hostname", false, "Show hostnames in table")
	showPorts := flag.Bool("port", false, "List unique ports with counts")
	showVendors := flag.Bool("vendor", false, "List vendors with counts")
	outputCSV := flag.Bool("csv", false, "Output in CSV format")
	flag.Parse()

	data, err := ioutil.ReadFile(*xmlFile)
	if err != nil {
		log.Fatalf("Erreur lecture fichier: %v", err)
	}

	var nmap NmapRun
	if err := xml.Unmarshal(data, &nmap); err != nil {
		log.Fatalf("Erreur parsing XML for %s: %v", *xmlFile, err)
	}

	// Mode 1 : -hostname -whereport
	if *showHostnames {
		ports := strings.Split(*wherePorts, ",")
		showAllPort := len(*wherePorts) == 0
		portSet := make(map[string]bool)
		for _, p := range ports {
			portSet[strings.TrimSpace(p)] = true
		}

		var results []HostInfo

		for _, h := range nmap.Hosts {
			var hostname, ipv4, mac, vendor string
			if len(h.Hostnames) > 0 {
				hostname = h.Hostnames[0].Name
			}
			for _, a := range h.Addresses {
				if a.AddrType == "ipv4" {
					ipv4 = a.Addr
				}
				if a.AddrType == "mac" {
					mac = a.Addr
					vendor = a.Vendor
				}
			}
			countOpen := 0
			match := false
			openPort := []string{}
			for _, p := range h.Ports {
				if p.State.State == "open" {
					countOpen++
					if showAllPort || portSet[strconv.Itoa(p.PortID)] {
						match = true
						openPort = append(openPort, strconv.Itoa(p.PortID))
					}
				}
			}
			if match {
				results = append(results, HostInfo{
					Hostname:  hostname,
					IPv4:      ipv4,
					MAC:       mac,
					Vendor:    vendor,
					CountOpen: countOpen,
					Ports:     strings.Join(openPort, ","),
				})
			}
		}

		sort.Slice(results, func(i, j int) bool {
			return results[i].CountOpen > results[j].CountOpen
		})

		if *outputCSV {
			w := csv.NewWriter(os.Stdout)
			defer w.Flush()
			w.Write([]string{"Hostname", "IPv4", "MAC", "Vendor", "CountOpenPort", "Ports"})
			for _, r := range results {
				w.Write([]string{r.Hostname, r.IPv4, r.MAC, r.Vendor, fmt.Sprint(r.CountOpen), r.Ports})
			}
		} else {
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "Hostname\tIPv4\tMAC\tVendor\tCountOpenPort\tPorts")
			fmt.Fprintln(w, "--------\t----\t---\t------\t-------------\t-----")
			for _, r := range results {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n", r.Hostname, r.IPv4, r.MAC, r.Vendor, r.CountOpen, r.Ports)
			}
			w.Flush()
		}
		return
	}

	// Mode 2 : -port
	if *showPorts {
		portMap := make(map[string]*PortInfo)

		for _, h := range nmap.Hosts {
			for _, p := range h.Ports {
				if p.State.State == "open" {
					key := fmt.Sprintf("%d/%s", p.PortID, p.Protocol)
					if _, ok := portMap[key]; !ok {
						portMap[key] = &PortInfo{Key: key, Service: p.Service.Name, Count: 0}
					}
					portMap[key].Count++
				}
			}
		}

		var ports []PortInfo
		for _, v := range portMap {
			ports = append(ports, *v)
		}
		sort.Slice(ports, func(i, j int) bool {
			return ports[i].Count > ports[j].Count
		})

		if *outputCSV {
			w := csv.NewWriter(os.Stdout)
			defer w.Flush()
			w.Write([]string{"Count", "Port/Proto", "ServiceName"})
			for _, v := range ports {
				w.Write([]string{fmt.Sprint(v.Count), v.Key, v.Service})
			}
		} else {
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "Count\tPort/Proto\tServiceName")
			fmt.Fprintln(w, "-----\t----------\t-----------")
			for _, v := range ports {
				fmt.Fprintf(w, "%d\t%s\t%s\n", v.Count, v.Key, v.Service)
			}
			w.Flush()
		}
		return
	}

	// Mode 3 : -vendor
	if *showVendors {
		vendorMap := make(map[string]int)
		for _, h := range nmap.Hosts {
			for _, a := range h.Addresses {
				if a.AddrType == "mac" {
					vendorMap[a.Vendor]++
				}
			}
		}

		var vendors []VendorInfo
		for k, v := range vendorMap {
			vendors = append(vendors, VendorInfo{Name: k, Count: v})
		}
		sort.Slice(vendors, func(i, j int) bool {
			return vendors[i].Count > vendors[j].Count
		})

		if *outputCSV {
			w := csv.NewWriter(os.Stdout)
			defer w.Flush()
			w.Write([]string{"Count", "VendorName"})
			for _, v := range vendors {
				w.Write([]string{fmt.Sprint(v.Count), v.Name})
			}
		} else {
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "Count\tVendorName")
			fmt.Fprintln(w, "-----\t----------")
			for _, v := range vendors {
				fmt.Fprintf(w, "%d\t%s\n", v.Count, v.Name)
			}
			w.Flush()
		}
		return
	}
}
