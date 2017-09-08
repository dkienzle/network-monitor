These are network monitoring tools written in Go.

My main goal was to learn Go and figure out whether it was the right tool for this job.  So far I've been pretty pleased 
with Go.

The tools here are _VERY_ rough.  I still need to refactor the code, and I'm still exploring the problem space.  But 
I wanted to get them posted here so I could start collecting feedback.

The tools thus far are:

listener -- monitors broadcast (and multicast) traffic and tells you what is on your network.  Collects ARP, DHCP, NetBIOS, 
Bonjour to try to provide sufficient detail to identify each system.  This can be run from any system on your network.

dnssniff -- monitors DNS requests and responses.  Needs to run on a mirror port or on the same box as your DNS server.

pcap_kafka -- a proof of concept tcpdump -> kafka tool

Other tools will be added later and these will be refined to work together.  


To build the tools, you need to install a recent version of Go (from www.golang.org).

Once Go is installed you need to retrieve the gopacket and kafka libraries
   go get github.com/google/gopacket
        go get github.com/confluentinc/confluent-kafka-go/kafka

If you want to capture traffic into a pcap file and then replay it, use tcpdump.  On the Mac the capture command looks like 
this:
   sudo tcpdump -w capturefile.pcap -i en0 -s0 ether multicast

This says to (w)rite a file called capturefile.pcap, recording from the en0 network (i)nterface, with a (s)naplength of 0
(capture the whole packet) and limit the capture to packets with the first bit = 1 (the ethernet broadcast bit)

On linux, use eth0 (for wired) or wlan0 (for wireless) instead of en0

On the Mac, I recommend changing the permissions on the bpf devices to allow your programs to monitor traffic without 
requiring sudo:
   sudo chgrp staff /dev/bpf*
   sudo chmod g+r /dev/bpf*
There is a startup item that ships with wireshark that will set these permissions each time the machine boots
