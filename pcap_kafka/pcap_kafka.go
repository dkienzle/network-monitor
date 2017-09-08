package main

import (
   "fmt"
   "github.com/google/gopacket"
   "github.com/google/gopacket/pcap"
	"github.com/confluentinc/confluent-kafka-go/kafka"
	"log"
   "time"
	"os"
)


var (
	brokers      string = "localhost:9092"
	device       string = "en0"
	topic        string = "test"
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
)

func min(a, b int) int {
        if a < b {
                return a
        }
        return b
}

func main() {

	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "Usage: %s <brokerlist> <device> <topic>\n", os.Args[0])
		os.Exit(1)
	}

	brokers = os.Args[1]
	device = os.Args[2]
	topic = os.Args[3]

	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)		
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

	p, err := kafka.NewProducer(&kafka.ConfigMap{"bootstrap.servers": brokers})

	if err != nil {
		fmt.Printf("Failed to create producer: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("Created Producer %v\n", p)

//	deliveryChan := make(chan kafka.Event)

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		// Process packet here
		var value [] byte = packet.Data()
		fmt.Println(packet.Metadata())
		p.ProduceChannel() <- &kafka.Message{TopicPartition: kafka.TopicPartition{Topic: &topic, Partition: kafka.PartitionAny}, Value: []byte(value)}

		//printPacketInfo(p, packet)
	}
}


