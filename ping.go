package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"net"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	timeSliceLength  = 8
	trackerLength    = 8
	protocolICMP     = 1
	protocolIPv6ICMP = 58
)

var (
	ipv4Proto = map[string]string{"ip": "ip4:icmp", "udp": "udp4"}
	ipv6Proto = map[string]string{"ip": "ip6:ipv6-icmp", "udp": "udp6"}
)

// Caller represents ICMP packet sender/receiver
type Caller struct {
	// Interval is the wait time between each packet send. Default is 1s.
	Interval time.Duration

	// Timeout specifies a timeout before ping exits, regardless of how many
	// packets have been received.
	Timeout time.Duration

	// Count tells pinger to stop after sending (and receiving) Count echo
	// packets. If this option is not specified, pinger will operate until
	// interrupted.
	Count int

	// Number of packets sent
	PacketsSent int

	// Number of packets received
	PacketsRecv int

	// rtts is all of the Rtts
	rtts []time.Duration

	// OnRecv is called when Caller receives and processes a packet
	OnRecv func(*Package)

	// OnFinish is called when Caller exits
	OnFinish func(*Record)

	// Size of packet being sent
	Size int

	// Tracker: Used to uniquely identify packet when non-priviledged
	Tracker int64

	// Source is the source IP address
	Source string

	// stop chan bool
	done chan bool

	ipAddr *net.IPAddr
	addr   string

	ipv4     bool
	size     int
	id       int
	sequence int
	network  string
}

type packet struct {
	bytes  []byte
	nbytes int
	ttl    int
}

// Package represents a received and processed ICMP echo packet.
type Package struct {
	// Rtt is the round-trip time it took to ping.
	Rtt time.Duration

	// IPAddr is the address of the host being pinged.
	IPAddr *net.IPAddr

	// Addr is the string address of the host being pinged.
	Addr string

	// NBytes is the number of bytes in the message.
	Nbytes int

	// Seq is the ICMP sequence number.
	Seq int

	// TTL is the Time To Live on the packet.
	Ttl int
}

// Record represent the stats of a currently running or finished
// pinger operation.
type Record struct {
	// PacketsRecv is the number of packets received.
	PacketsRecv int

	// PacketsSent is the number of packets sent.
	PacketsSent int

	// PacketLoss is the percentage of packets lost.
	PacketLoss float64

	// IPAddr is the address of the host being pinged.
	IPAddr *net.IPAddr

	// Addr is the string address of the host being pinged.
	Addr string

	// Rtts is all of the round-trip times sent via this pinger.
	Rtts []time.Duration

	// MinRtt is the minimum round-trip time sent via this pinger.
	MinRtt time.Duration

	// MaxRtt is the maximum round-trip time sent via this pinger.
	MaxRtt time.Duration

	// AvgRtt is the average round-trip time sent via this pinger.
	AvgRtt time.Duration

	// StdDevRtt is the standard deviation of the round-trip times sent via
	// this pinger.
	StdDevRtt time.Duration
}

// NewPinger returns a new Caller struct pointer
func NewPinger(addr string) (*Caller, error) {
	//get the IP and Error
	ipAddr, err := net.ResolveIPAddr("ip", addr)
	//if there is an error, return nil for caller and the err
	if err != nil {
		return nil, err
	}

	var ipv4bool bool
	ipv4bool = isIPv4(ipAddr.IP)

	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	//return a pointer to a Caller and nil for error
	return &Caller{
		ipAddr:   ipAddr,
		addr:     addr,
		Interval: time.Second,
		Timeout:  time.Second * 100000,
		Count:    -1,
		id:       r.Intn(math.MaxInt16),
		network:  "udp",
		ipv4:     ipv4bool,
		Size:     timeSliceLength,
		Tracker:  r.Int63n(math.MaxInt64),
		done:     make(chan bool),
	}, nil
}

// Run runs the caller. This is a blocking function that will exit when it's
// done. If Count or Interval are not specified, it will run continuously until
// it is interrupted.
func (p *Caller) Run() {
	p.run()
}

func (p *Caller) run() {
	//packet endpoint
	var conn *icmp.PacketConn
	//check if p is ipv4 or ipv6
	if p.ipv4 {
		if conn = p.listen(ipv4Proto[p.network]); conn == nil {
			return
		}
		_ = conn.IPv4PacketConn().SetControlMessage(ipv4.FlagTTL, true)
	} else {
		if conn = p.listen(ipv6Proto[p.network]); conn == nil {
			return
		}
		_ = conn.IPv6PacketConn().SetControlMessage(ipv6.FlagHopLimit, true)
	}

	defer conn.Close()
	defer p.finish()

	var wg sync.WaitGroup
	//start a slice of packet channels
	recv := make(chan *packet, 5)
	defer close(recv)
	//increment the wait group count
	wg.Add(1)
	go p.recvICMP(conn, recv, &wg)

	err := p.sendICMP(conn)
	if err != nil {
		fmt.Println(err.Error())
	}

	timeout := time.NewTicker(p.Timeout)
	defer timeout.Stop()
	interval := time.NewTicker(p.Interval)
	defer interval.Stop()

	for {
		select {
		case <-p.done:
			wg.Wait()
			return
		case <-timeout.C:
			close(p.done)
			wg.Wait()
			fmt.Println("time exceeded")
			return
		case <-interval.C:
			if p.Count > 0 && p.PacketsSent >= p.Count {
				continue
			}
			err = p.sendICMP(conn)
			if err != nil {
				fmt.Println("FATAL: ", err.Error())
			}
		case r := <-recv:
			err := p.processPacket(r)
			if err != nil {
				fmt.Println("FATAL: ", err.Error())
			}
		}
		if p.Count > 0 && p.PacketsRecv >= p.Count {
			close(p.done)
			wg.Wait()
			return
		}
	}
}

func (p *Caller) Stop() {
	close(p.done)
}

func (p *Caller) finish() {
	handler := p.OnFinish
	if handler != nil {
		s := p.Statistics()
		handler(s)
	}
}

// Record returns the statistics of the pinger. This can be run while the
// pinger is running or after it is finished. OnFinish calls this function to
// get it's finished statistics.
func (p *Caller) Statistics() *Record {
	loss := float64(p.PacketsSent-p.PacketsRecv) / float64(p.PacketsSent) * 100
	var min, max, total time.Duration
	if len(p.rtts) > 0 {
		min = p.rtts[0]
		max = p.rtts[0]
	}
	for _, rtt := range p.rtts {
		if rtt < min {
			min = rtt
		}
		if rtt > max {
			max = rtt
		}
		total += rtt
	}
	s := Record{
		Rtts:        p.rtts,
		Addr:        p.addr,
		IPAddr:      p.ipAddr,
		PacketsSent: p.PacketsSent,
		PacketsRecv: p.PacketsRecv,
		PacketLoss:  loss,
		MaxRtt:      max,
		MinRtt:      min,
	}
	if len(p.rtts) > 0 {
		s.AvgRtt = total / time.Duration(len(p.rtts))
		var sumSquares time.Duration
		for _, rtt := range p.rtts {
			sumSquares += (rtt - s.AvgRtt) * (rtt - s.AvgRtt)
		}
		s.StdDevRtt = time.Duration(math.Sqrt(
			float64(sumSquares / time.Duration(len(p.rtts)))))
	}
	return &s
}

func (p *Caller) recvICMP(
	conn *icmp.PacketConn,
	recv chan<- *packet,
	wg *sync.WaitGroup,
) {
	defer wg.Done()
	for {
		select {
		case <-p.done:
			return
		default:
			bytesReceived := make([]byte, 512)
			_ = conn.SetReadDeadline(time.Now().Add(time.Millisecond * 100))
			var n, ttl int
			var err error
			if p.ipv4 {
				var ipv4cm *ipv4.ControlMessage
				n, ipv4cm, _, err = conn.IPv4PacketConn().ReadFrom(bytesReceived)
				if ipv4cm != nil {
					ttl = ipv4cm.TTL
				}
			} else {
				var ipv6cm *ipv6.ControlMessage
				n, ipv6cm, _, err = conn.IPv6PacketConn().ReadFrom(bytesReceived)
				if ipv6cm != nil {
					ttl = ipv6cm.HopLimit
				}
			}

			if err != nil {
				netErr, state := err.(*net.OpError)
				if state {
					//fmt.Println(netErr.Error())
					if netErr.Timeout() {
						// Read timeout
						continue
					} else {
						close(p.done)
						return
					}
				}

			}

			recv <- &packet{bytes: bytesReceived, nbytes: n, ttl: ttl}
		}
	}
}

func (p *Caller) processPacket(recv *packet) error {
	receivedTime := time.Now()
	var proto int
	if p.ipv4 {
		proto = protocolICMP
	} else {
		proto = protocolIPv6ICMP
	}

	var m *icmp.Message
	var err error
	if m, err = icmp.ParseMessage(proto, recv.bytes); err != nil {
		return fmt.Errorf("error parsing icmp message: %s", err.Error())
	}

	if m.Type != ipv4.ICMPTypeEchoReply && m.Type != ipv6.ICMPTypeEchoReply {
		// Not an echo reply, ignore it
		return nil
	}

	outPkt := &Package{
		Nbytes: recv.nbytes,
		IPAddr: p.ipAddr,
		Addr:   p.addr,
		Ttl:    recv.ttl,
	}

	switch pkt := m.Body.(type) {
	case *icmp.Echo:

		if len(pkt.Data) < timeSliceLength+trackerLength {
			return fmt.Errorf("insufficient data received; got: %d %v",
				len(pkt.Data), pkt.Data)
		}

		tracker := bytesToInt(pkt.Data[timeSliceLength:])
		timestamp := bytesToTime(pkt.Data[:timeSliceLength])

		if tracker != p.Tracker {
			return nil
		}

		outPkt.Rtt = receivedTime.Sub(timestamp)
		outPkt.Seq = pkt.Seq
		p.PacketsRecv++
	default:
		// Very bad, not sure how this can happen
		return fmt.Errorf("invalid ICMP echo reply; type: '%T', '%v'", pkt, pkt)
	}

	p.rtts = append(p.rtts, outPkt.Rtt)
	handler := p.OnRecv
	if handler != nil {
		handler(outPkt)
	}

	return nil
}

func (p *Caller) sendICMP(conn *icmp.PacketConn) error {
	var typ icmp.Type
	if p.ipv4 {
		typ = ipv4.ICMPTypeEcho
	} else {
		typ = ipv6.ICMPTypeEchoRequest
	}

	var dst net.Addr = p.ipAddr
	if p.network == "udp" {
		dst = &net.UDPAddr{IP: p.ipAddr.IP, Zone: p.ipAddr.Zone}
	}

	t := append(timeToBytes(time.Now()), intToBytes(p.Tracker)...)
	if remainSize := p.Size - timeSliceLength - trackerLength; remainSize > 0 {
		t = append(t, bytes.Repeat([]byte{1}, remainSize)...)
	}

	body := &icmp.Echo{
		ID:   p.id,
		Seq:  p.sequence,
		Data: t,
	}

	msg := &icmp.Message{
		Type: typ,
		Code: 0,
		Body: body,
	}

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return err
	}

	for {
		if _, err := conn.WriteTo(msgBytes, dst); err != nil {
			if neterr, ok := err.(*net.OpError); ok {
				if neterr.Err == syscall.ENOBUFS {
					continue
				}
			}
		}
		p.PacketsSent++
		p.sequence++
		break
	}

	return nil
}

func (p *Caller) listen(netProto string) *icmp.PacketConn {
	conn, err := icmp.ListenPacket(netProto, p.Source)
	if err != nil {
		fmt.Printf("Error listening for ICMP packets: %s\n", err.Error())
		close(p.done)
		return nil
	}
	return conn
}

func bytesToTime(b []byte) time.Time {
	var nsec int64
	for i := uint8(0); i < 8; i++ {
		nsec += int64(b[i]) << ((7 - i) * 8)
	}
	return time.Unix(nsec/1000000000, nsec%1000000000)
}

func isIPv4(ip net.IP) bool {
	return len(ip.To4()) == net.IPv4len
}

func timeToBytes(t time.Time) []byte {
	nsec := t.UnixNano()
	b := make([]byte, 8)
	for i := uint8(0); i < 8; i++ {
		b[i] = byte((nsec >> ((7 - i) * 8)) & 0xff)
	}
	return b
}

func bytesToInt(b []byte) int64 {
	return int64(binary.BigEndian.Uint64(b))
}

func intToBytes(tracker int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(tracker))
	return b
}
