package main

import (
	"log"
	"net"
	"time"
)

var client_name = "test"

func processIncomingPacket(addr *net.UDPAddr, packet []byte) {
	packetType := packet[4]
	switch packetType {
	case helloType:
		log.Printf("Hello from %s", addr)
	case publicKeyType:
		log.Printf("Public Key from %s", addr)
	case helloReplyType:
		log.Printf("HelloReply from %s", addr)
	case errorType:
		log.Printf("Error: %s from %s", string(packet[headerLength:]), addr)
	default:
		log.Printf("Packet type=%d from %s", packetType, addr)

	}
}

func sendPeriodicHello(conn *net.UDPConn, addresses [][]byte) {
	for {
		for _, addr := range addresses {
			dst, err := net.ResolveUDPAddr("udp", string(addr))
			if err != nil {
				log.Fatal(err)
			}
			conn.WriteToUDP(makeHello(1, client_name), dst)
			// the protocol requires an Id different from 0 for unsolicited messages
		}
		time.Sleep(helloPeriod)
	}
}

func receiveIncomingMessages(connection *net.UDPConn) {
	for {
		buffer := make([]byte, 1024)
		n, remoteAddr, err := 0, new(net.UDPAddr), error(nil)
		for err == nil {
			n, remoteAddr, err = connection.ReadFromUDP(buffer)
			go processIncomingPacket(remoteAddr, buffer[:n])
		}
	}
}

func main() {
	juliuszAddresses, err := getPeerAddresses(juliusz)
	if err != nil {
		log.Fatalf("can't retrieve Juliusz' DFS node addresses: %s", err)
		return
	}

	for _, addr := range juliuszAddresses {
		log.Printf("Juliusz' DFS node address: %s\n", string(addr))
	}

	addr := net.UDPAddr{
		Port: 12345,
		IP:   net.IP{0, 0, 0, 0}, // listen to all addresses
	}

	connection, err := net.ListenUDP("udp", &addr)
	if err != nil {
		panic(err)
	}

	//quit := make(chan struct{})

	go sendPeriodicHello(connection, juliuszAddresses)
	// for i := 0; i < runtime.NumCPU(); i++
	go receiveIncomingMessages(connection)

	for {
	}
}
