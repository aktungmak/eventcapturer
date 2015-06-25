package main

import (
	"flag"
	"fmt"
	snmp "github.com/aktungmak/wapsnmp"
	"github.com/glycerine/rbuf"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"time"
)

// simple oid/value pair to be passed between goroutines
type OidInfo struct {
	Oid   string
	Value interface{}
	Host  net.UDPAddr
}

// this gets started in its own goroutine
// it will take incoming traps and forward the OIDs via a chan
func TrapServer(listenIPAddr string, port int, oidoutput chan OidInfo) {
	addr := net.UDPAddr{
		Port: port,
		IP:   net.ParseIP(listenIPAddr),
	}
	conn, err := net.ListenUDP("udp", &addr)

	defer conn.Close()
	if err != nil {
		log.Printf("UDP listen error: %s\n", err)
		return
	}

	wsnmp := snmp.NewWapSNMPOnConn("", "", snmp.SNMPv2c, 2*time.Second, 5, conn)
	defer wsnmp.Close()

	packet := make([]byte, 2048)
	for {
		_, addr, err := conn.ReadFromUDP(packet)
		if err != nil {
			log.Printf("UDP read error: %s\n", err)
		}

		oids, err := wsnmp.ParseTrap(packet)
		if err != nil {
			log.Printf("Error processing trap: %v.", err)
		}
		for oid, value := range oids {
			oi := OidInfo{
				Oid:   oid,
				Value: value,
				Host:  *addr,
			}
			log.Printf("%v", oi)
			oidoutput <- oi

		}
	}
}

func OidFilter(oidinput chan OidInfo, oidoutput chan OidInfo, oids ...string) {
	for {
		oi := <-oidinput
		// take a look through the filter list and see if this is there
		for _, foid := range oids {
			if strings.Contains(oi.Oid, foid) {
				// its in the filter list, so let it through
				oidoutput <- oi
				break
			}
		}
	}
}

// represents a circular buffer of UDP data that can be dumped
// to a file. When DumpNow() is called, it waits Pause seconds
// before dumping, to catch data de
type CircularNetCap struct {
	Addr   net.IP
	Port   int
	Ifce   net.IP //TODO: this is not used by Start() yet
	Pause  time.Duration
	buffer *rbuf.AtomicFixedSizeRingBuf
}

// constructor, creates a new struct and allocates the buffer
// does not open a port yet, must call Start() to do that
func NewCircularNetCap(addr string, port int, ifce string, pause, bufsize int) *CircularNetCap {
	buf := rbuf.NewAtomicFixedSizeRingBuf(bufsize)

	return &CircularNetCap{
		Addr:   net.ParseIP(addr),
		Port:   port,
		Ifce:   net.ParseIP(ifce),
		Pause:  time.Duration(pause) * time.Second,
		buffer: buf,
	}
}

// open a port and if all is well start the run() goroutine
// otherwise return an error and do nothing
func (c *CircularNetCap) Start() (err error) {
	addr := net.UDPAddr{
		Port: c.Port,
		IP:   c.Addr,
	}

	// the stream may be unicast or multicast, so choose appropriately
	var conn *net.UDPConn
	if c.Addr.IsMulticast() {
		conn, err = net.ListenMulticastUDP("udp", nil, &addr) //TODO use the ifce
	} else {
		conn, err = net.ListenUDP("udp", &addr)
	}

	if err != nil {
		conn.Close()
		return err
	}

	go c.run(conn)
	return nil
}

// this runs in a goroutine to perform the work of capturing
func (c *CircularNetCap) run(conn *net.UDPConn) {
	defer conn.Close()
	packet := make([]byte, 4096)
	for {
		n, _, err := conn.ReadFromUDP(packet)
		if err != nil {
			log.Printf("TS capture error: %s", err)
			continue
		}
		c.buffer.Write(packet[:n])

	}
}

// goroutine to export the current buffer contents to a file
// triggered by a message coming in on the input channel
func (c *CircularNetCap) TriggerListener(input chan OidInfo) {
	log.Printf("start")
	for {
		<-input
		// time.Sleep(c.Pause) DEBUG
		c.DumpNow()
	}
}

func (c *CircularNetCap) DumpNow() {
	tdate := time.Now().Format("2006-01-02T15-04-05")
	fname := fmt.Sprintf("%s;%d_%s.ts", c.Addr, c.Port, tdate)
	data := c.buffer.Bytes(true)
	err := ioutil.WriteFile(fname, data, 0644)
	if err != nil {
		log.Printf("Error saving TS capture: %s", err)
	} else {
		log.Printf("Saved capture %s!", fname)
	}
}

func main() {
	// add cmdline flags
	var mcast = flag.String("mcast", "224.1.2.1", "multicast to capture")
	var port = flag.Int("port", 2000, "udp port to listen on")
	var ifce = flag.String("ifce", "0.0.0.0", "(not implemented yet) interface address to listen on")
	var pause = flag.Int("pause", 10, "post-roll in seconds after trigger before dumping file")
	var bufSize = flag.Int("bufsiz", 5000000, "size of ring buffer in bytes")
	var trigOid = flag.String("oid", ".", "oid to trigger dump in dotted decimal format")

	flag.Parse()

	// buffer size = (bitrate / 8) * (pause * 2)
	cnc := NewCircularNetCap(*mcast, *port, *ifce, *pause, *bufSize)
	cnc.Start()

	trapServerToFilter := make(chan OidInfo, 10)
	filterToCtrl := make(chan OidInfo, 10)

	go TrapServer("0.0.0.0", 162, trapServerToFilter)
	go OidFilter(trapServerToFilter, filterToCtrl, *trigOid)
	go cnc.TriggerListener(filterToCtrl)

	// for {
	// 	oid := <-filterToCtrl
	// 	log.Printf("main got: %s", oid)
	// }

	time.Sleep(5 * time.Second)

	filterToCtrl <- OidInfo{}

	for {
		fmt.Printf("\rWaiting for triggers   ")
		time.Sleep(1 * time.Second)
		fmt.Printf("\rWaiting for triggers.  ")
		time.Sleep(1 * time.Second)
		fmt.Printf("\rWaiting for triggers.. ")
		time.Sleep(1 * time.Second)
		fmt.Printf("\rWaiting for triggers...")
		time.Sleep(1 * time.Second)
	}
}
