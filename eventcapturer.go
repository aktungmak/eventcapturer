package main

import (
	snmp "github.com/aktungmak/wapsnmp"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"
)

// this gets started in its own goroutine
// it will take incoming traps and forward the OIDs via a chan
func TrapServer(listenIPAddr string, port int, oidoutput chan string) error {
	addr := net.UDPAddr{
		Port: port,
		IP:   net.ParseIP(listenIPAddr),
	}
	conn, err := net.ListenUDP("udp", &addr)
	defer conn.Close()
	if err != nil {
		log.Printf("udp Listen error.")
		return err
	}

	wsnmp := setupTrapListener(conn)
	defer wsnmp.Close()

	packet := make([]byte, 3000)
	for {
		_, _, err := conn.ReadFromUDP(packet)
		if err != nil {
			log.Printf("udp read error: %s\n", err)
		}

		// log.Printf("Received trap from %s\n", addr.IP)

		oids, err := wsnmp.ParseTrap(packet)
		if err != nil {
			log.Printf("Error processing trap: %v.", err)
		}
		for oid, _ := range oids {
			// log.Printf("%s: %v\n", oid, value)
			oidoutput <- oid
		}
	}

	return nil
}

func setupTrapListener(udpsock net.Conn) *snmp.WapSNMP {
	wsnmp := snmp.NewWapSNMPOnConn("", "", snmp.SNMPv2c, 2*time.Second, 5, udpsock)

	wsnmp.Trapusers = append(wsnmp.Trapusers, snmp.V3user{"pcb.snmpv3", "SHA1", "this_is_my_pcb", "AES", "my_pcb_is_4_me"})

	return wsnmp
}

func OidFilter(oidinput chan string, oidoutput chan string, oids ...string) {
	for {
		oid := <-oidinput
		// take a look through the filter list and see if this is there
		for _, foid := range oids {
			if strings.Contains(oid, foid) {
				// its in the filter list, so let it through
				oidoutput <- oid
				break
			}
		}
	}
}

func main() {
	rand.Seed(0)

	tsToFilter := make(chan string, 10)
	filterToCtrl := make(chan string, 10)

	go TrapServer("0.0.0.0", 162, tsToFilter)
	go OidFilter(tsToFilter, filterToCtrl)

	for {
		oid := <-filterToCtrl
		log.Printf("main got: %s", oid)
	}

}
