package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// need to add the parameter parsing stuff.  For now just assume that you
// read a file if a name is given, otherwise set up listening to en0
func main() {
	iface := flag.String("i", "", "interface for live listening")
	filename := flag.String("r", "", "pcap file for replay")
	flag.Parse()

	if (*iface == "" && *filename == "") || (*iface != "" && *filename != "") {
		flag.Usage()
		log.Fatal("Must specify either an interface with -i or a capture file with -f")
	}

	if *iface != "" {
		liveMain(*iface)
	} else {
		fileMain(*filename)
	}

}

func fileMain(filename string) {

	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		log.Fatal("PCAP OpenOffline error (handle to read packet):", err)
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

	devices := make(DeviceList) //make(map[string]*Device)

	for packet := range packetSource.Packets() {
		// Process packet here
		devices.recordPacketInfo(packet)
	}

	devices.writeSummary()

}

func liveMain(iface string) {

	snapshotLen := int32(1500)
	promiscuous := false
	timeout := 30 * time.Second

	handle, err := pcap.OpenLive(iface, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
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

	devices := make(DeviceList) //make(map[string]*Device)

	for packet := range packetSource.Packets() {
		// Process packet here
		devices.recordPacketInfo(packet)
	}

	devices.writeSummary()
}
