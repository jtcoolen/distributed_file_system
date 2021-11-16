package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"log"
	"net"
	"time"
)

type Node struct {
	name               string
	privateKey         *ecdsa.PrivateKey
	publicKey          *ecdsa.PublicKey
	formattedPublicKey [64]byte
	conn               *net.UDPConn
	bootstrapAddresses [][]byte
}

var client_name = "test2"

func processIncomingPacket(node *Node, addr *net.UDPAddr, packet []byte) {
	packetType := packet[4]
	id := binary.BigEndian.Uint32(packet[0:4])
	switch packetType {
	case helloType:
		log.Printf("Hello from %s", addr)
	case helloReplyType:
		log.Printf("HelloReply from %s", addr)
	case publicKeyType:
		log.Printf("Public Key from %s", addr)
		reply, err := makePublicKeyReply(id, node)
		if err == nil {
			node.conn.WriteToUDP(reply, addr)
			break
		}
		log.Printf("%s", err)
	case publicKeyReplyType:
		log.Printf("publicKeyReply from %s", addr)
	case rootType:
		log.Printf("Root from %s", addr)
		reply, err := makeRootReply(id, sha256.Sum256([]byte("")), node)
		if err == nil {
			node.conn.WriteToUDP(reply, addr)
			break
		}
		log.Printf("%s", err)
	case rootReplyType:
		log.Printf("RootReply from %s", addr)
	case errorType:
		log.Printf("Error: %s from %s", string(packet[headerLength:]), addr)
	default:
		log.Printf("Packet type=%d from %s", packetType, addr)

	}
}

func sendPeriodicHello(node *Node) {
	for {
		for _, addr := range node.bootstrapAddresses {
			dst, err := net.ResolveUDPAddr("udp", string(addr))
			if err != nil {
				log.Fatal(err)
			}
			hello, err := makeHello(1, node)
			// the protocol requires an Id different from 0 for unsolicited messages
			if err == nil {
				node.conn.WriteToUDP(hello, dst)
				continue
			}
			log.Printf("%s", err)

		}
		time.Sleep(helloPeriod)
	}
}

func receiveIncomingMessages(node *Node) {
	for {
		buffer := make([]byte, 1024)
		n, remoteAddr, err := 0, new(net.UDPAddr), error(nil)
		for err == nil {
			n, remoteAddr, err = node.conn.ReadFromUDP(buffer)
			go processIncomingPacket(node, remoteAddr, buffer[:n])
		}
	}
}

func main() {

	publicKey, privateKey, err := genECDSAKeyPair()
	if err != nil {
		log.Fatal("Couldn't generate ECDSA key pair")
		return
	}

	formattedPublicKey := getFormattedECDSAPublicKey(publicKey)

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

	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		panic(err)
	}

	node := Node{client_name, privateKey, publicKey, formattedPublicKey, conn, juliuszAddresses}

	//quit := make(chan struct{})

	go sendPeriodicHello(&node)
	// for i := 0; i < runtime.NumCPU(); i++
	go receiveIncomingMessages(&node)

	for {
	}
}
