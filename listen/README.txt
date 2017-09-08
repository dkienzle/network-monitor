
This tool monitors broadcast (and multicast) traffic in order to get a sense of what is on the network.
It can be run on a switched network without a mirror port, because broadcasts are intended to be sent to every host.  It also
opportunistically collects multicast traffic that makes it to the listening system -- some day I'll figure out how to game the
IGMP protocol and get the machine added to any multicast groups that it wants to observe.

If you want to capture traffic into a pcap file and then replay it, use tcpdump.  On the Mac the capture command looks like this
   sudo tcpdump -w capturefile.pcap -i en0 -s0 ether multicast

On linux, use eth0 (for wired) or wlan0 (for wireless) instead of en0

Once you have a capture file, invoke the listener with:
   go run listener.go capturefile.pcap

The listener takes a while to build because the gopacket library initializes static variables with the complete MAC->manufacturer listings.
This is extremely useful but does bloat the code and build time.

The listener will process each packet in turn.  It will collect summary data for each device it sees talking on the network.  If it sees
a packet it doesn't recognize, it will hexdump a copy of that packet to the screen, but will suppress future packets from that device to
the same UDP destination port.  Once it has processed all the packets, it will dump a summary of the devices it has seen in IP order.

Each device will list:
 - the MAC address / manufacturer
 - the IP / IPv6 address
 - the NetBIOS and DHCP client names
 - a list of UDP ports it has sent traffic to
 - a list of the Bonjour Questions (Q) and Answers/Authorities (A,B,C) it has sent

The log list of to do items is in a separate TODO.txt file.  Please feel free to suggest others.
