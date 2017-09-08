
This is a tool for listening to a device using pcap and writing the capture results to Kafka.

It is extremely rough -- really just a proof of concept and a demonstration to myself that Go can easily read pcap and write kafka.

Some planned improvements:
 - improve the command line arguments
 - write the pcap header into the Kafka topic
 - create a separate goroutine so we can provide stats and even a rudimentary command line UI (think "top")
 - figure out how to pull the packets out of Kafka and into the gopacket structure (define a Kafka packet source)

Obviously you need to make sure that your communications with Kafka get excluded from listening by the interface/filter you define...
