package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// globals.  from the pcap sample code.  except they stupidly the len to 1024 which caused all sorts of decoding errors
var (
	device       string = "en0"
	snapshot_len int32  = 1500
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
)

type Device struct {
	MAC          string
	manufacturer string
	IPv4         net.IP
	clientID     string
	NBNames      map[string]int
	dnsnames     map[string]uint64
}

var Devices map[string]*Device

// every function named init() is called at load time to initialize globals
func init() {
	Devices = make(map[string]*Device)
}

type ByMAC []*Device

func (a ByMAC) Len() int           { return len(a) }
func (a ByMAC) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByMAC) Less(i, j int) bool { return a[i].MAC < a[j].MAC }

type ByIP []*Device

func (a ByIP) Len() int           { return len(a) }
func (a ByIP) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByIP) Less(i, j int) bool { return string(a[i].IPv4) < string(a[j].IPv4) }

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// need to add the parameter parsing stuff.  For now just assume that you
// read a file if a name is given, otherwise set up listening to en0
func main() {

	if len(os.Args) > 1 {
		fname := os.Args[1]
		handle, err = pcap.OpenOffline(fname)
		if err != nil {
			log.Fatal("PCAP OpenOffline error (handle to read packet):", err)
		}
	} else {
		handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)

		if err != nil {
			log.Fatal(err)
		}
	}
	defer handle.Close()

	// Set filter
	//	var filter string = "ether multicast"
	//	err = handle.SetBPFFilter(filter)
	//	if err != nil {
	//		log.Fatal(err)
	//	}
	//	fmt.Println("Only capturing multicast packets.")

	layers.RegisterUDPPortLayerType(5353, layers.LayerTypeDNS)

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		// Process packet here
		printPacketInfo(packet)
	}

	writeSummary()
}

func writeSummary() {

	// Go randomizes the iterator order for a map on purpose.  So to get them into a consistent order, we need to sort first.
	// For now sort by MAC address since that's easiest, since they are constant over the years, and since many systems have
	// more than one MAC that are close together
	sorted := make([]*Device, len(Devices))
	i := 0

	for _, entry := range Devices {
		sorted[i] = entry
		i++
	}

	//   sort.Sort(ByMAC(sorted))
	sort.Sort(ByIP(sorted))

	fmt.Println()
	for _, d := range sorted {
		fmt.Println()
		fmt.Printf("%20s %20s %20s\n", d.MAC, d.clientID, d.IPv4)
		for n, u := range d.dnsnames {
			fmt.Printf("%d\t%s\n", u, n)
		}
	}

}

// Retrieve the device record for this MAC address.
// If this is the first time we have seen this MAC,
// create a new record and _initialize_ the fields!
func getDevice(mac net.HardwareAddr) *Device {
	d, ok := Devices[string(mac)]
	if ok {
		return d
	}

	var newDevice Device
	newDevice.NBNames = make(map[string]int)
	newDevice.dnsnames = make(map[string]uint64)
	newDevice.MAC = mac.String()

	Devices[string(mac)] = &newDevice
	return &newDevice
}

func printPacketInfo(packet gopacket.Packet) {
	// Let's see if the packet is an ethernet packet
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)

	if ethernetLayer == nil {
		fmt.Println("No ethernet layer detected!")
		return
	}

	ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)

	srcMAC := ethernetPacket.SrcMAC.String()
	d := getDevice(ethernetPacket.SrcMAC)

	dstMAC := ethernetPacket.DstMAC.String()

	//	fmt.Println("Ethernet packet: ",srcMAC,"   ",dstMAC)
	//	fmt.Printf("Ethernet type: %d, %s\n", ethernetPacket.EthernetType,ethernetPacket.EthernetType)
	switch ethernetPacket.EthernetType {

	case layers.EthernetTypeIPv4:
		//		fmt.Println("Found an IPv4")
		PrintIPv4Info(d, packet, srcMAC, dstMAC)

	case layers.EthernetTypeARP:
		arpLayer := packet.Layer(layers.LayerTypeARP)
		arp, _ := arpLayer.(*layers.ARP)

		if len(d.IPv4) == 0 || d.IPv4.IsUnspecified() {
			d.IPv4 = net.IP(arp.SourceProtAddress)
		}

	default:
		fmt.Printf("UNKNOWN PACKET FROM %s to %s\n", srcMAC, dstMAC)
	}

	return
}

func dumpDNS(d *Device, packet gopacket.Packet, request bool) bool {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		fmt.Println("Error decoding DNS packet")
		return false
	}

	dns, _ := dnsLayer.(*layers.DNS)

	if request {
		for _, q := range dns.Questions {
			d.dnsnames[string(q.Name)]++
		}
	} else {
		for i, a := range dns.Answers {
			fmt.Printf("\tAnswer[%d]: %s\t%s\n", i, a.Name, a.String())
		}
		for i, a := range dns.Authorities {
			fmt.Printf("\tAuthority[%d]: %s\t%s\n", i, a.Name, a.String())
		}
		for i, a := range dns.Additionals {
			fmt.Printf("\tAdditional[%d]: %s\t%s\n", i, a.Name, a.String())
		}
	}

	return true
}

func PrintIPv4Info(d *Device, packet gopacket.Packet, srcMAC, dstMAC string) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	ip, _ := ipLayer.(*layers.IPv4)

	if !ip.SrcIP.IsUnspecified() {
		d.IPv4 = ip.SrcIP
	}

	switch ip.Protocol {

	case layers.IPProtocolUDP:

		dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
		if dhcpLayer != nil {
			dhcp, _ := dhcpLayer.(*layers.DHCPv4)

			hostname := ""
			for _, o := range dhcp.Options {
				if o.Type == layers.DHCPOptHostname {
					hostname = string(o.Data)
				}
			}

			fmt.Printf("DHCP %s ", dhcp.Operation)
			fmt.Printf("from %s / %s to %s ", ip.SrcIP, srcMAC, ip.DstIP)
			fmt.Printf("hostname: %s\n", hostname)

			if hostname == "" {
				fmt.Println(" %q", dhcp.Options)
			} else {
				d.clientID = hostname
			}

			return
		}

		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)

			// if we have never seen traffic to this port from this system before, dump the packat
			if udp.DstPort == 53 {
				if !dumpDNS(d, packet, true) {
					applicationLayer := packet.ApplicationLayer()
					if applicationLayer != nil {
						Hexdump(applicationLayer.Payload())
					} else {
						fmt.Println("Argh!  No application layer")
					}
				}
			}
			if udp.SrcPort == 53 {
				dumpDNS(d, packet, false)
			}

		}
		return

	case layers.IPProtocolTCP:

		// Honestly, for multicast, we should NEVER see TCP...
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)

			if tcp.DstPort == 53 {
				if !dumpDNS(d, packet, true) {
					applicationLayer := packet.ApplicationLayer()
					if applicationLayer != nil {
						Hexdump(applicationLayer.Payload())
					} else {
						fmt.Println("Argh!  No application layer")
					}
				}
			}

			if tcp.SrcPort == 53 {
				dumpDNS(d, packet, false)
			}
		}
		return

	}
}

func DumpUnknown(packet gopacket.Packet) {

	fmt.Println("All packet layers:")
	for _, layer := range packet.Layers() {
		fmt.Println("- ", layer.LayerType())
	}
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		Hexdump(applicationLayer.Payload())
	}
}

func Hexdump(data []byte) {
	for i := 0; i < len(data); i += 16 {
		Dumpline(uint32(i), data[i:min(i+16, len(data))])
	}
}

func Dumpline(addr uint32, line []byte) {
	fmt.Printf("\t0x%04x: ", int32(addr))
	var i uint16
	for i = 0; i < 16 && i < uint16(len(line)); i++ {
		if i%2 == 0 {
			os.Stdout.WriteString(" ")
		}
		fmt.Printf("%02x", line[i])
	}
	for j := i; j <= 16; j++ {
		if j%2 == 0 {
			os.Stdout.WriteString(" ")
		}
		os.Stdout.WriteString("  ")
	}
	os.Stdout.WriteString("  ")
	for i = 0; i < 16 && i < uint16(len(line)); i++ {
		if line[i] >= 32 && line[i] <= 126 {
			fmt.Printf("%c", line[i])
		} else {
			os.Stdout.WriteString(".")
		}
	}
	os.Stdout.WriteString("\n")
}
