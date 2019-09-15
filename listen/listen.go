package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// need to add the parameter parsing stuff.  For now just assume that you
// read a file if a name is given, otherwise set up listening to en0
func main() {

	devices := make(DeviceList) //make(map[string]*Device)

	device := "en0"
	snapshotLen := int32(1500)
	promiscuous := false
	timeout := 30 * time.Second
	var handle *pcap.Handle
	var err error

	if len(os.Args) > 1 {
		fname := os.Args[1]
		handle, err = pcap.OpenOffline(fname)
		if err != nil {
			log.Fatal("PCAP OpenOffline error (handle to read packet):", err)
		}
	} else {
		handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)

		if err != nil {
			log.Fatal(err)
		}
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
		devices.recordPacketInfo(packet)
	}

	devices.writeSummary()
}
