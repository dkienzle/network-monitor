
package main

import (
   "fmt"
   "github.com/google/gopacket"
   "github.com/google/gopacket/pcap"
   "github.com/google/gopacket/macs"
   "github.com/google/gopacket/layers"
	"log"
	"bytes"
   "time"
	"net"
	"os"
	"strconv"
	"sort"
	"unicode"
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

type PortSet map[int]bool


func (p PortSet) String() string {
	var retval bytes.Buffer
	delim := ""

	for port,_ := range p {
		retval.WriteString(delim)
		retval.WriteString(strconv.Itoa(port))
		delim = ","
	}
	return retval.String()
}

type Device struct {
	MAC       string
	manufacturer string
	IPv4         net.IP
	clientID  string
	NBNames map[string]int
	IPv6    net.IP
	packets   uint64
	ports PortSet
	snap bool
	WOMP bool
	bonjourQ map[string]bool
	bonjourA map[string][]byte
	bonjourB map[string][]byte
	bonjourC map[string][]byte
   // need some sort of timestamp
	// need some sort of activity total.... possibly with decay
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

	if (len(os.Args) > 1) {
		fname := os.Args[1]
		handle, err = pcap.OpenOffline(fname)
      if err != nil {
         log.Fatal("PCAP OpenOffline error (handle to read packet):", err)
      }
	} else {
		handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)		

		if err != nil {log.Fatal(err) }
	}
	defer handle.Close()

	// Set filter
	var filter string = "ether multicast"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Only capturing multicast packets.")
	
	layers.RegisterUDPPortLayerType(5353, layers.LayerTypeDNS)
		
	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		// Process packet here
		printPacketInfo(packet)
	}

	writeSummary()
}

func (d *Device) bump() {
	d.packets++
}

func writeSummary() {

	// Go randomizes the iterator order for a map on purpose.  So to get them into a consistent order, we need to sort first.
	// For now sort by MAC address since that's easiest, since they are constant over the years, and since many systems have
	// more than one MAC that are close together
	sorted := make([]*Device, len(Devices))
   i := 0

   for  _, entry := range Devices {
      sorted[i] = entry
      i++
   }

//   sort.Sort(ByMAC(sorted))
   sort.Sort(ByIP(sorted))
	
	fmt.Println()
	for _,d := range sorted {
		fmt.Println()
		fmt.Printf("%20s %20s %20s %30s %30s %8d %t\n",d.MAC, d.clientID, d.IPv4, d.IPv6, d.manufacturer, d.packets, d.snap)
		fmt.Println("\tUDP Ports:",d.ports)
		for n,c := range d.NBNames {
			fmt.Printf("\tNetBIOS (%d) = %s\n",c,n)
		}
		for n,_ := range d.bonjourQ {
			fmt.Println("\tQ:",n)
		}
		for n,_ := range d.bonjourA {
			fmt.Println("\tA:",n)
			//Hexdump(x)
		}
		for n,_ := range d.bonjourB {
			fmt.Println("\tB:",n)
			//Hexdump(x)
		}
		for n,_ := range d.bonjourC {
			fmt.Println("\tC:",n)
			//Hexdump(x)
		}		
	}
	
}

func getOrgName(mac []byte) string {
	var prefix [3]byte 
	prefix[0] = mac[0]
	prefix[1] = mac[1]
	prefix[2] = mac[2]
	
	return macs.ValidMACPrefixMap[prefix]		
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
	newDevice.ports = make(map[int]bool)
	newDevice.bonjourQ = make(map[string]bool)
	newDevice.bonjourA = make(map[string][]byte)
	newDevice.bonjourB = make(map[string][]byte)
	newDevice.bonjourC = make(map[string][]byte)
	newDevice.MAC = mac.String()
	
	newDevice.manufacturer = getOrgName(mac)
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
	d.bump()
	
	dstMAC := ethernetPacket.DstMAC.String()

//	fmt.Println("Ethernet packet: ",srcMAC,"   ",dstMAC)
//	fmt.Printf("Ethernet type: %d, %s\n", ethernetPacket.EthernetType,ethernetPacket.EthernetType)
	switch ethernetPacket.EthernetType {

	case layers.EthernetTypeLLC:
		dumpLLC(d, packet, srcMAC, dstMAC)
		
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
		
	default:
		fmt.Printf("UNKNOWN PACKET FROM %s to %s\n",srcMAC, dstMAC)
		Hexdump(packet.Data())
	}

	return
}


func dumpWOMP(d *Device, srcMAC string, packet gopacket.Packet) {
	//WOL packet
	// [0-5] FF's
	// [6-11] src MAC
	// [12=13] ethertype
	// [14=19] FF's
	// [20-25] dst MAC

	p := packet.Data()[20:]
	dstMAC := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",p[0],p[1],p[2],p[3],p[4],p[5])
	fmt.Printf("WOMP packet from %s to %s\n",srcMAC,dstMAC)
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
		return "",0
	}
	// if there are no questions, bail
	if (b[4] == 0) && (b[5] == 0) {
		return "",0
	}

	var name bytes.Buffer
	length := int(b[12])
	fmt.Println("length = ",length)
	for i := 13; i < 13 + length; i+=2 {
		char := rune((b[i]-65)*16+b[i+1]-65)
		if unicode.IsPrint(char) {
			name.WriteString(string(char))
			//		fmt.Println("name = ",name.String())
		}
	}
	// 0x2910 is the flags for Registation broadcast, allow recursion 
	//if (b[2] != 41) || (b[3] != 16) {
	//	return ""
	//}
	return name.String(), (int(b[2])*256)+int(b[3])

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


func dumpLLC(d *Device, packet gopacket.Packet, srcMAC, dstMAC string) {
	llcLayer := packet.Layer(layers.LayerTypeLLC)
	llc, ok := llcLayer.(*layers.LLC)

	if !ok {
		fmt.Println("Unable to decode LLC packet")
		Hexdump(packet.Data())
		return
	}
	
	snapLayer := packet.Layer(layers.LayerTypeSNAP)
	snap, ok := snapLayer.(*layers.SNAP)

	fmt.Printf("LLC/SNAP packet from %s to %s \n",srcMAC, dstMAC)
	fmt.Printf("\tDSAP: %d SSAP:%d CR:%t IG:%t  Control: %d\n",llc.DSAP, llc.SSAP, llc.CR, llc.IG, llc.Control)
	if ok {
		d.snap = true;
		fmt.Printf("\tOrg: %x (%s)  Type: %s\n", snap.OrganizationalCode, getOrgName(snap.OrganizationalCode),  snap.Type.String())
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
		fmt.Printf("ICMP packet from %s / %s to %s / %s\n",ip.SrcIP, srcMAC, ip.DstIP, dstMAC)
		if icmpLayer != nil {
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			fmt.Printf("\t%s\n",icmp.TypeCode)
		}
		return
		
	case layers.IPProtocolUDP:
	
		dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
		if dhcpLayer != nil {
			dhcp, _ := dhcpLayer.(*layers.DHCPv4)

			hostname := ""
			for _,o := range dhcp.Options {
				if o.Type == layers.DHCPOptHostname {
					hostname = string(o.Data)
				}
			}

			fmt.Printf("DHCP %s ",dhcp.Operation)
			fmt.Printf("from %s / %s to %s ", ip.SrcIP, srcMAC, ip.DstIP)
			fmt.Printf("hostname: %s\n", hostname)

			
			if hostname == "" {
				fmt.Println(" %q",dhcp.Options)
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
					if !dumpBonjour(d,packet) {
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
						name,code := extractNetBiosName(applicationLayer.Payload())
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
			if (ok) {
				fmt.Printf("%s from %s to %s \n",igmp.Type,ip.SrcIP,igmp.GroupAddress)
			} else {
				igmp, ok := igmpLayer.(*layers.IGMPv1or2)
				if (ok) {
					fmt.Printf("%s from %s to %s \n",igmp.Type,ip.SrcIP,igmp.GroupAddress)
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
        fmt.Printf( "\t0x%04x: ", int32(addr))
        var i uint16
        for i = 0; i < 16 && i < uint16(len(line)); i++ {
                if i%2 == 0 {
                        os.Stdout.WriteString(" ")
                }
                fmt.Printf( "%02x", line[i])
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
