package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"
)

var usage = `
usage:
    ./main [-c count] [-i interval] [-t timeout] [--privileged] host
`

func main() {
	//use flag to parse command line input
	timeout := flag.Duration("t", time.Second*100000, "")
	interval := flag.Duration("i", time.Second, "")
	count := flag.Int("c", -1, "")
	privileged := flag.Bool("privileged", false, "")

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
	pinger, err := NewPinger(host)
	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
		return
	}

	// listen for ctrl-C signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for _ = range c {
			pinger.Stop()
		}
	}()



	pinger.OnRecv = func(pkt *Package) {
		fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v ttl=%v\n",
			pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt, pkt.Ttl)
	}

	pinger.OnFinish = func(stats *Record) {
		fmt.Printf("\n--- %s ping statistics ---\n", stats.Addr)
		fmt.Printf("%d packets transmitted, %d packets received, %v%% packet loss\n",
			stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
		fmt.Printf("round-trip min/avg/max/stddev = %v/%v/%v/%v\n",
			stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt)
	}

	pinger.Count = *count
	pinger.Interval = *interval
	pinger.Timeout = *timeout
	pinger.SetPrivileged(*privileged)

	fmt.Printf("PING %s (%s):\n", pinger.Addr(), pinger.IPAddr())
	pinger.Run()
}
