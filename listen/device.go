package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"unicode"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/macs"
)

type PortSet map[int]bool

type MAC [6]byte

func (m MAC) toString() string {
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5])
}

func (p PortSet) String() string {
	var retval bytes.Buffer
	delim := ""

	for port := range p {
		retval.WriteString(delim)
		retval.WriteString(strconv.Itoa(port))
		delim = ","
	}
	return retval.String()
}

type Device struct {
	mac          MAC
	manufacturer string
	IPv4         net.IP
	clientID     string
	NBNames      map[string]int
	IPv6         net.IP
	packets      uint64
	ports        PortSet
	snap         bool
	WOMP         bool
	bonjourQ     map[string]bool
	bonjourA     map[string][]byte
	bonjourB     map[string][]byte
	bonjourC     map[string][]byte
	// need some sort of timestamp
	// need some sort of activity total.... possibly with decay
}

type DeviceList map[MAC]*Device

// every function named init() is called at load time to initialize globals

type ByMAC []*Device

func (a ByMAC) Len() int           { return len(a) }
func (a ByMAC) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByMAC) Less(i, j int) bool { return string(a[i].mac[:]) < string(a[j].mac[:]) }

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

func (d *Device) bump() {
	d.packets++
}

func (devices DeviceList) writeSummary() {
	//TODO -- change this to print the deltas that we observed in the last tick.
	//new devices, number of packets, any other interesting "facts"
	fmt.Printf("Monitoring %d devices\n", len(devices))
}

func (devices DeviceList) writeDetail() {

	// Go randomizes the iterator order for a map on purpose.  So to get them into a consistent order,
	// we need to sort first.  For now sort by MAC address since that's easiest, since they are constant
	// over the years, and since many systems have more than one MAC that are close together
	sorted := make([]*Device, len(devices))
	i := 0

	for _, entry := range devices {
		sorted[i] = entry
		i++
	}

	//   sort.Sort(ByMAC(sorted))
	sort.Sort(ByIP(sorted))

	fmt.Println()
	for _, d := range sorted {
		fmt.Println()
		fmt.Printf("%8d %20s %20s %20s %-30s %30s %t\n", d.packets, d.mac.toString(), d.clientID, d.IPv4, d.manufacturer, d.IPv6, d.snap)
		fmt.Println("\tUDP Ports:", d.ports)
		for n, c := range d.NBNames {
			fmt.Printf("\tNetBIOS (%d) = %s\n", c, n)
		}
		for n := range d.bonjourQ {
			fmt.Println("\tQ:", n)
		}
		for n := range d.bonjourA {
			fmt.Println("\tA:", n)
			//Hexdump(x)
		}
		for n := range d.bonjourB {
			fmt.Println("\tB:", n)
			//Hexdump(x)
		}
		for n := range d.bonjourC {
			fmt.Println("\tC:", n)
			//Hexdump(x)
		}
	}

}

func getOrgName(snapCode []byte) string {
	if len(snapCode) < 3 {
		return "invalid"
	}
	var prefix [3]byte
	copy(prefix[:], snapCode[0:3])

	name, ok := macs.ValidMACPrefixMap[prefix]
	if ok {
		return name
	}
	return "unknown"
}

func makeMAC(hwaddr net.HardwareAddr) (MAC, error) {
	var mac MAC
	if len(hwaddr) != 6 {
		return mac, fmt.Errorf("invalid hardware address %v", hwaddr)
	}

	copy(mac[:], hwaddr[0:6])
	return mac, nil
}

func NewDevice(mac MAC) *Device {

	device := Device{}
	device.NBNames = make(map[string]int)
	device.ports = make(map[int]bool)
	device.bonjourQ = make(map[string]bool)
	device.bonjourA = make(map[string][]byte)
	device.bonjourB = make(map[string][]byte)
	device.bonjourC = make(map[string][]byte)
	device.mac = mac

	device.manufacturer = getOrgName(mac[:])
	return &device
}

// Retrieve the device record for this MAC address.
// If this is the first time we have seen this MAC,
// create a new record and _initialize_ the fields!
func (devices DeviceList) getDevice(hwaddr net.HardwareAddr) (*Device, error) {
	mac, err := makeMAC(hwaddr)
	if err != nil {
		return nil, err //TODO: wrap the error
	}

	device, ok := devices[mac]
	if ok {
		return device, nil
	}

	d := NewDevice(mac)
	devices[mac] = d
	return d, nil
}

func (devices *DeviceList) recordPacketInfo(packet gopacket.Packet, verbose bool) {
	// Let's see if the packet is an ethernet packet
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)

	if ethernetLayer == nil {
		fmt.Println("No ethernet layer detected!")
		return
	}

	ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)

	srcMAC := ethernetPacket.SrcMAC.String()
	d, _ := devices.getDevice(ethernetPacket.SrcMAC) //TODO -- probably should log a bad MAC
	d.bump()

	dstMAC := ethernetPacket.DstMAC.String()

	//	fmt.Println("Ethernet packet: ",srcMAC,"   ",dstMAC)
	//	fmt.Printf("Ethernet type: %d, %s\n", ethernetPacket.EthernetType,ethernetPacket.EthernetType)
	switch ethernetPacket.EthernetType {

	case layers.EthernetTypeLLC:
		dumpLLC(d, packet, srcMAC, dstMAC, verbose)

	case layers.EthernetTypeIPv4:
		//		fmt.Println("Found an IPv4")
		PrintIPv4Info(d, packet, srcMAC, dstMAC)

	case layers.EthernetTypeIPv6:
		ipLayer := packet.Layer(layers.LayerTypeIPv6)
		ip, _ := ipLayer.(*layers.IPv6)

		if !ip.SrcIP.IsUnspecified() {
			d.IPv6 = ip.SrcIP
		}

	case layers.EthernetTypeARP:
		arpLayer := packet.Layer(layers.LayerTypeARP)
		arp, _ := arpLayer.(*layers.ARP)

		//		fmt.Printf("ARP %s ",arp.Operation)
		//		fmt.Printf("from  %s / %s / %s ",srcMAC, net.IP(arp.SourceProtAddress), d.manufacturer)
		//		fmt.Printf("to %s / %s\n",dstMAC, net.IP(arp.DstProtAddress))
		// for devices that aren't telling us there IP any other way...

		if len(d.IPv4) == 0 || d.IPv4.IsUnspecified() {
			d.IPv4 = net.IP(arp.SourceProtAddress)
		}

	case 0x0842:
		dumpWOMP(d, srcMAC, packet)

	case 0x8874:
		// loop detection.  for now just eat it because we don't believe the source MAC anyway.
		fmt.Printf("Loop Detection protocol 0x8874\n")
		if verbose {
			Hexdump(packet.Data())
		}

	default:
		fmt.Printf("UNKNOWN %x PACKET FROM %s to %s\n", ethernetPacket.EthernetType, srcMAC, dstMAC)
		if verbose {
			Hexdump(packet.Data())
		}
	}

}

func dumpWOMP(d *Device, srcMAC string, packet gopacket.Packet) {
	//WOL packet
	// [0-5] FF's
	// [6-11] src MAC
	// [12=13] ethertype
	// [14=19] FF's
	// [20-25] dst MAC

	p := packet.Data()[20:]
	dstMAC := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", p[0], p[1], p[2], p[3], p[4], p[5])
	fmt.Printf("WOMP packet from %s to %s\n", srcMAC, dstMAC)
	d.WOMP = true
}

// this is a nasty kludge to pull the first question record out of a NetBios Name Service packet
// the "right way" to do this would be to define a new decoder for netbios, but that is overkill
// for my purposes.
// NBNS: 2 byte ID, 2 byte flags, then 2-byte ints for questions, answers, authority, other.
// then the quesitons are a single character length field and an array of encoded "nibbles"
func extractNetBiosName(b []byte) (string, int) {
	// if the packet is too short to contain a single question, bail
	if len(b) < 13 {
		return "", 0
	}
	// if there are no questions, bail
	if (b[4] == 0) && (b[5] == 0) {
		return "", 0
	}

	var name bytes.Buffer
	length := int(b[12])
	fmt.Println("length = ", length)
	for i := 13; i < 13+length; i += 2 {
		char := rune((b[i]-65)*16 + b[i+1] - 65)
		if unicode.IsPrint(char) {
			name.WriteString(string(char))
			//		fmt.Println("name = ",name.String())
		}
	}
	// 0x2910 is the flags for Registation broadcast, allow recursion
	//if (b[2] != 41) || (b[3] != 16) {
	//	return ""
	//}
	return name.String(), (int(b[2]) * 256) + int(b[3])

}

func dumpBonjour(d *Device, packet gopacket.Packet) bool {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		fmt.Println("Error decoding Bonjour packet")
		return false
	}

	dns, _ := dnsLayer.(*layers.DNS)

	for _, q := range dns.Questions {
		//fmt.Printf("\tQuestion[%d]: %s\n",i,q.Name)
		d.bonjourQ[string(q.Name)] = true
	}

	for _, a := range dns.Answers {
		//fmt.Printf("\tAnswer[%d]: %s\t%s\n",i,a.Name,a.String())
		d.bonjourA[string(a.Name)] = a.Data
	}
	for _, a := range dns.Authorities {
		//fmt.Printf("\tAuthority[%d]: %s\t%s\n",i,a.Name,a.String())
		d.bonjourB[string(a.Name)] = a.Data
	}
	for _, a := range dns.Additionals {
		//fmt.Printf("\tAdditional[%d]: %s\t%s\n",i,a.Name,a.String())
		d.bonjourC[string(a.Name)] = a.Data
	}

	return true
}

func dumpLLC(d *Device, packet gopacket.Packet, srcMAC, dstMAC string, verbose bool) {
	llcLayer := packet.Layer(layers.LayerTypeLLC)
	llc, ok := llcLayer.(*layers.LLC)

	if !ok {
		fmt.Println("Unable to decode LLC packet")
		if verbose {
			Hexdump(packet.Data())
		}
		return
	}

	snapLayer := packet.Layer(layers.LayerTypeSNAP)
	snap, ok := snapLayer.(*layers.SNAP)

	fmt.Printf("LLC/SNAP packet from %s to %s \n", srcMAC, dstMAC)
	fmt.Printf("\tDSAP: %d SSAP:%d CR:%t IG:%t  Control: %d\n", llc.DSAP, llc.SSAP, llc.CR, llc.IG, llc.Control)
	if ok {
		d.snap = true
		fmt.Printf("\tOrg: %x (%s)  Type: %s\n", snap.OrganizationalCode, getOrgName(snap.OrganizationalCode), snap.Type.String())
	}
}

func PrintIPv4Info(d *Device, packet gopacket.Packet, srcMAC, dstMAC string) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	ip, _ := ipLayer.(*layers.IPv4)

	if !ip.SrcIP.IsUnspecified() {
		d.IPv4 = ip.SrcIP
	}

	switch ip.Protocol {

	case layers.IPProtocolICMPv4:

		icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
		fmt.Printf("ICMP packet from %s / %s to %s / %s\n", ip.SrcIP, srcMAC, ip.DstIP, dstMAC)
		if icmpLayer != nil {
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			fmt.Printf("\t%s\n", icmp.TypeCode)
		}
		return

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
			if !d.ports[int(udp.DstPort)] {
				fmt.Printf("UDP packet from %s:%d to %s:%d\n ", ip.SrcIP, udp.SrcPort, ip.DstIP, udp.DstPort)

				if udp.DstPort == 5353 {
					if !dumpBonjour(d, packet) {
						applicationLayer := packet.ApplicationLayer()
						if applicationLayer != nil {
							Hexdump(applicationLayer.Payload())
						} else {
							fmt.Println("Argh!  No application layer")
						}
						DumpUnknown(packet)
					}
				} else if udp.DstPort == 137 {
					applicationLayer := packet.ApplicationLayer()
					if applicationLayer != nil {
						name, code := extractNetBiosName(applicationLayer.Payload())
						if name != "" {
							d.NBNames[name] = code
						} else {
							fmt.Println("No NetBIOS name found in ")
							Hexdump(applicationLayer.Payload())
						}
					}

				} else {
					applicationLayer := packet.ApplicationLayer()
					if applicationLayer != nil {
						Hexdump(applicationLayer.Payload())
					}
				}
			}
			// record that we've seen it.
			d.ports[int(udp.DstPort)] = true

		}
		return

	case layers.IPProtocolTCP:

		// Honestly, for multicast, we should NEVER see TCP...
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			fmt.Println("TCP layer detected.")
			tcp, _ := tcpLayer.(*layers.TCP)

			// TCP layer variables:
			// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
			// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
			fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
			fmt.Println("Sequence number: ", tcp.Seq)
			fmt.Println()
		}
		return

	case layers.IPProtocolIGMP:
		igmpLayer := packet.Layer(layers.LayerTypeIGMP)
		if igmpLayer != nil {
			igmp, ok := igmpLayer.(*layers.IGMP)
			if ok {
				fmt.Printf("AAA - %s from %s to %s \n", igmp.Type, ip.SrcIP, igmp.GroupAddress)
				Hexdump(ip.Payload)
			} else {
				igmp, ok := igmpLayer.(*layers.IGMPv1or2)
				if ok {
					fmt.Printf("AAB - %s from %s to %s \n", igmp.Type, ip.SrcIP, igmp.GroupAddress)
					Hexdump(igmp.Payload)
				} else {
					fmt.Println("Huh?")
					DumpUnknown(packet)
				}
			}
		}

		return

	default:
		// If we get here, it's because we ran into something we didn't handle yet.

		DumpUnknown(packet)
		// Iterate over all layers, printing out each layer type
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
