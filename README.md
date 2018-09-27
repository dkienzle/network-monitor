These are network monitoring tools written in Go (as a learning exercise -- I don't claim to be a Go expert).

The tools here are _VERY_ rough.  I still need to refactor the code, and I'm still exploring the problem space.  But 
I wanted to get them posted here so I could start collecting feedback.

The tools thus far are:

listener -- monitors broadcast (and multicast) traffic and tells you what is on your network.  Collects ARP, DHCP, NetBIOS, 
Bonjour to try to provide sufficient detail to identify each system.  This can be run from any system on your network.

dnssniff -- monitors DNS requests and responses.  Needs to run on a mirror port or on the same box as your DNS server.

pcap_kafka -- a proof of concept tcpdump -> kafka tool

Other tools will be added later and these will be refined to work together.  

##Quick Start:
- install a recent version of Go (from www.golang.org).

- Once Go is installed you need to retrieve the gopacket and kafka libraries

  go get github.com/google/gopacket

  go get github.com/confluentinc/confluent-kafka-go/kafka

- On a Mac you can eliminate the need to run using sudo by giving your account privilege to read the pcap device(s)

  sudo chgrp staff /dev/bpf*

  sudo chmod g+r /dev/bpf*

(This will be reverted any time you reboot the Mac)

- build and run the listener against the default interface

  [sudo] go run listen/listener.go

This will run and dump info about packets until you hit Ctrl-C.

In the current incarnation, running against the live interface will not show you the device summary.  For that, you need to
capture broadcast traffic into a pcap file and then replay it aginst the listener in offline mode.  This will also work on linux
(which uses a different device name than the hardcoded Mac default) and will allow you to avoid running my code as root.

  sudo tcpdump -w capturefile.pcap -i en0 -s0 ether multicast

    On linux, use eth0 (for wired) or wlan0 (for wireless) instead of en0

  go run listen/listener.go capturefile.pcap
 
