package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"
)

var usage = "usage:\n./go_ping [-c count] [-i interval] [-t timeout] host"


func main() {
	//use flag to parse command line input
	timeout := flag.Duration("t", time.Second*100000, "")
	interval := flag.Duration("i", time.Second, "")
	count := flag.Int("c", -1, "")
	flag.Usage = func() {
		//if there is no input then print usage
		fmt.Printf(usage)
	}
	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		return
	}

	host := flag.Arg(0)
	caller, err := NewPinger(host)


	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
		return
	} else if timeout.Milliseconds() <= 0{
		fmt.Println("ping: invalid timeout: `0s'")
		return
	}

	// listen for ctrl-C signal
		c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for _ = range c {
			caller.Stop()
		}
	}()

	caller.OnRecv = func(pkt *Package) {
		fmt.Printf("%d bytes from %s: icmp_seq=%d ttl=%v time=%v\n",
			pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Ttl, pkt.Rtt)
	}

	caller.OnFinish = func(stats *Record) {
		fmt.Printf("\n--- %s ping statistics ---\n", stats.Addr)
		fmt.Printf("%d packets transmitted, %d packets received, %v%% packet loss\n",
			stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
		fmt.Printf("round-trip min = %v, avg = %v, max = %v, stddev = %v.\n",
			stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt)
	}

	caller.Count = *count
	caller.Interval = *interval
	caller.Timeout = *timeout

	fmt.Printf("PING %s (%s):\n", caller.addr, caller.ipAddr)
	caller.Run()
}
