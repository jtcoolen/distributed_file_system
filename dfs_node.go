package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"log"
	"net"
	"time"

	lru "github.com/hashicorp/golang-lru"
)

type Node struct {
	name               string
	privateKey         *ecdsa.PrivateKey
	publicKey          *ecdsa.PublicKey
	formattedPublicKey [64]byte
	conn               *net.UDPConn
	bootstrapAddresses [][]byte
	incomingPackets    *lru.ARCCache
}

var clientName = "HTTP200JokesAreOK"
var incomingPacketsLRUCacheSize = 100

func processIncomingPacket(node *Node, addr *net.UDPAddr, packet []byte) {
	packetType := packet[4]
	id := binary.BigEndian.Uint32(packet[0:4])
	packetLength := binary.BigEndian.Uint16(packet[5:headerLength])
	switch packetType {
	case helloType:
		log.Printf("Hello from %s", addr)

	case helloReplyType:
		log.Printf("HelloReply(%s) from %s", packet[headerLength:headerLength+int(packetLength)], addr)
	case publicKeyType:
		log.Printf("Public Key from %s", addr)
		reply, err := makePublicKeyReply(id, node)
		if err == nil {
			node.conn.WriteToUDP(reply, addr)
			break
		}
		log.Printf("%s", err)
	case publicKeyReplyType:
		log.Printf("publicKeyReply(%x) from %s", packet[headerLength:headerLength+int(packetLength)], addr)
	case rootType:
		log.Printf("Root(%x) from %s", packet[headerLength:headerLength+int(packetLength)], addr)
		reply, err := makeRootReply(id, sha256.Sum256([]byte("")), node)
		if err == nil {
			node.conn.WriteToUDP(reply, addr)
			break
		}
		log.Printf("%s", err)
	case rootReplyType:
		log.Printf("RootReply from %s", addr)
	case getDatumType:
		log.Printf("GetDatum from %s", addr)
	case datumType:
		log.Printf("Datum(%x) from %s with id %d", packet[headerLength:headerLength+int(packetLength)], addr, id)
		kind := packet[headerLength+hashLength]
		switch kind {
		case 0: // chunk
			log.Print("Got chunk")
		case 1: // tree
			len := int(packetLength) - 1
			log.Printf("Got tree, len=%d", len)
			var h [32]byte
			for i := 0; i < len/32; i += 1 {
				copy(h[:], packet[headerLength+hashLength+1+i*32:headerLength+hashLength+1+i*32+32])

				for _, addr := range node.bootstrapAddresses {

					hello, err := makeGetDatum(uint32(i+1), h, node)
					if err != nil {
						log.Fatal(err)
					}
					dst, err := net.ResolveUDPAddr("udp", string(addr))
					if err != nil {
						log.Fatal(err)
					}

					if err == nil {
						log.Printf("Sent GetDatum(%x)!", h)
						node.conn.WriteToUDP(hello, dst)
						continue
					}
				}
			}
		case 2: // directory
			len := int(packetLength) - 1
			log.Printf("Got directory, len=%d", len)
			var h [32]byte
			for i := 0; i < len/64; i += 1 {
				copy(h[:], packet[headerLength+hashLength+1+32+i*64:headerLength+hashLength+1+i*64+32+32])
				log.Printf("Entry name: %s", packet[headerLength+hashLength+1+i*64:headerLength+hashLength+1+i*64+32])
				for _, addr := range node.bootstrapAddresses {

					hello, err := makeGetDatum(uint32(i+1), h, node)
					if err != nil {
						log.Fatal(err)
					}
					dst, err := net.ResolveUDPAddr("udp", string(addr))
					if err != nil {
						log.Fatal(err)
					}

					if err == nil {
						log.Printf("Sent GetDatum(%x)!", h)
						node.conn.WriteToUDP(hello, dst)
						continue
					}
				}
			}

		}
		node.incomingPackets.Add(id, kind)
	case noDatumType:
		log.Printf("NoDatum from %s", addr)
	case errorType:
		log.Printf("Error: %s from %s", string(packet[headerLength:headerLength+int(packetLength)]), addr)
	default:
		log.Printf("Packet type=%d from %s", packetType, addr)
	}
}

func sendPeriodicHello(node *Node) {
	i := 0
	for {
		for _, addr := range node.bootstrapAddresses {
			dst, err := net.ResolveUDPAddr("udp", string(addr))
			if err != nil {
				log.Fatal(err)
			}

			if i == 1 {
				log.Print("Ok i == 1")
				juliuszRoot, _ := getPeerRoot(juliusz)
				hello, err := makeGetDatum(1, juliuszRoot, node)
				if err == nil {
					log.Printf("Sent GetDatum(%x)!", juliuszRoot)
					node.conn.WriteToUDP(hello, dst)
					continue
				}
			}

			hello, err := makeHello(1, node)
			if err == nil {
				log.Print("Sent hello!")
				node.conn.WriteToUDP(hello, dst)
				continue
			}
			log.Printf("%s", err)

		}
		i++
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

func downloadJuliuszTree() {

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

	cache, err := lru.NewARC(incomingPacketsLRUCacheSize)
	if err != nil {
		panic(err)
	}

	node := Node{clientName,
		privateKey,
		publicKey,
		formattedPublicKey,
		conn,
		juliuszAddresses,
		cache,
	}

	for _, addr := range node.bootstrapAddresses {
		hello, err := makeHello(1, &node)
		if err != nil {
			log.Fatal(err)
		}
		dst, err := net.ResolveUDPAddr("udp", string(addr))
		if err != nil {
			log.Fatal(err)
		}

		if err == nil {
			log.Print("Sent hello!")
			node.conn.WriteToUDP(hello, dst)
			continue
		}
	}

	//quit := make(chan struct{})

	go sendPeriodicHello(&node)
	// for i := 0; i < runtime.NumCPU(); i++
	go receiveIncomingMessages(&node)

	for {
	}
}
