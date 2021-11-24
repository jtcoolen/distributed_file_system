package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"log"
	"net"
	"time"
)

type Node struct {
	name                 string
	privateKey           *ecdsa.PrivateKey
	publicKey            *ecdsa.PublicKey
	formattedPublicKey   [64]byte
	conn                 *net.UDPConn
	bootstrapAddresses   []*net.UDPAddr
	pendingPacketQueries map[uint32]chan []byte
}

var clientName = "HTTP200JokesAreOK"

func processIncomingPacket(node *Node, addr *net.UDPAddr, packet []byte) {
	id := binary.BigEndian.Uint32(packet[0:4])
	packetType := packet[4]
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
		//log.Printf("RootReply from %s", addr)

	case getDatumType:
		//log.Printf("GetDatum from %s", addr)

	case datumType:
		//log.Printf("Datum(%x) from %s with id %d", packet[headerLength:headerLength+int(packetLength)], addr, id)
		if node.pendingPacketQueries[id] != nil {
			node.pendingPacketQueries[id] <- packet[:headerLength+int(packetLength)]
		}

	case noDatumType:
		//log.Printf("NoDatum(%x) from %s", packet[headerLength:headerLength+int(packetLength)], addr)
		if node.pendingPacketQueries[id] != nil {
			node.pendingPacketQueries[id] <- packet[:headerLength+int(packetLength)]
		}

	case errorType:
		log.Printf("Error: %s from %s", string(packet[headerLength:headerLength+int(packetLength)]), addr)

	default:
		log.Printf("Packet type=%d from %s", packetType, addr)
	}
}

func sendPeriodicHello(node *Node) {
	i := 0
	for {
		time.Sleep(helloPeriod)
		for _, addr := range node.bootstrapAddresses {
			hello, err := makeHello(1, node)
			if err == nil {
				log.Print("Sent hello!")
				node.conn.WriteToUDP(hello, addr)
				continue
			}
			log.Printf("%s", err)
		}
		log.Printf("Incoming Messages Table Length = %d", len(node.pendingPacketQueries))
		i++
	}
}

func receiveIncomingMessages(node *Node) {
	for {
		buffer := make([]byte, 8192) // TODO: be careful when parsing
		n, remoteAddr, err := 0, new(net.UDPAddr), error(nil)
		for err == nil {
			n, remoteAddr, err = node.conn.ReadFromUDP(buffer)
			go processIncomingPacket(node, remoteAddr, buffer[:n])
		}
	}
}

func waitPacket(id uint32, packet []byte, node *Node) []byte { // TODO: return error after max retries
	var delay time.Duration = 200000000
	limit := time.After(delay)

	var v chan []byte = node.pendingPacketQueries[id]

	if v != nil {
		defer delete(node.pendingPacketQueries, id)

		for {
			select {
			case out := <-v:
				return out

			case <-limit:
				_, err := node.conn.WriteToUDP(packet, node.bootstrapAddresses[0])
				if err != nil {
					log.Fatal(err)
				}
				delay = delay * delay
				limit = time.After(delay)
			}
		}
	}
	return nil
}

func downloadJuliuszTree(node *Node) Entry {
	juliuszRoot, _ := getPeerRoot(juliusz)

	root := Entry{Directory, "", juliuszRoot, nil}
	var currentEntry *Entry

	var id uint32 = 2 // TODO: global id variable?
	hashes := make([][32]byte, 0)
	hashes = append(hashes, juliuszRoot)

	for len(hashes) != 0 {
		id++

		datum, err := makeGetDatum(id, hashes[0], node)
		if err != nil {
			log.Fatal(err)
		}
		node.pendingPacketQueries[id] = make(chan []byte)

		_, err = node.conn.WriteToUDP(datum, node.bootstrapAddresses[0])
		if err != nil {
			log.Fatal(err)
		}

		node.pendingPacketQueries[id] = make(chan []byte)
		packet := waitPacket(id, datum, node) // TODO: check if packet is valid
		if packet[4] == noDatumType {
			log.Print("No Datum!")
			return root
		}

		currentEntry = findEntry(hashes[0], &root)

		hashes = hashes[1:] // Remove processed hash

		packetLength := binary.BigEndian.Uint16(packet[5:headerLength])
		// TODO: check if announced packet size is correct, or detect if a datagram contains multiple messages

		kind := packet[headerLength+hashLength]
		var h [32]byte

		switch kind {
		case 0: // Chunk
			currentEntry.entryType = Chunk
			copy(h[:], packet[headerLength:headerLength+hashLength])

		case 1: // Tree
			currentEntry.entryType = Tree
			len := int(packetLength) - 1 - hashLength
			log.Printf("Tree : %x", packet[headerLength+hashLength:])
			for i := 0; i < len/32; i += 1 {
				copy(h[:], packet[headerLength+hashLength+1+i*32:headerLength+hashLength+1+i*32+32])
				hashes = append(hashes, h)
				currentEntry.children = append(currentEntry.children, &Entry{Chunk, "", h, nil})
			}

		case 2: // Directory
			currentEntry.entryType = Directory
			len := int(packetLength) - 1 - hashLength
			for i := 0; i < len/64; i += 1 {
				copy(h[:], packet[headerLength+hashLength+1+32+i*64:headerLength+hashLength+1+i*64+32+32])
				name := packet[headerLength+hashLength+1+i*64 : headerLength+hashLength+1+i*64+32]
				hashes = append(hashes, h)
				currentEntry.children = append(currentEntry.children, &Entry{Directory, string(name), h, nil})
			}
		}
	}
	return root
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

	bootstrapAddresses := make([]*net.UDPAddr, len(juliuszAddresses))

	for i, addr := range juliuszAddresses {
		log.Printf("Juliusz' DFS node address: %s\n", string(addr))
		dst, err := net.ResolveUDPAddr("udp", string(addr))
		if err != nil {
			log.Fatal(err)
		}
		bootstrapAddresses[i] = dst
	}

	addr := net.UDPAddr{
		Port: 12345,
		IP:   net.IP{0, 0, 0, 0}, // listen to all addresses
	}

	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		panic(err)
	}

	node := Node{clientName,
		privateKey,
		publicKey,
		formattedPublicKey,
		conn,
		bootstrapAddresses,
		make(map[uint32]chan []byte),
	}

	for _, addr := range node.bootstrapAddresses {
		hello, err := makeHello(1, &node)
		if err != nil {
			log.Fatal(err)
		}

		if err == nil {
			log.Print("Sent hello!")
			node.conn.WriteToUDP(hello, addr)
			continue
		}
	}

	go sendPeriodicHello(&node)
	go receiveIncomingMessages(&node)

	var delay time.Duration = 8 * time.Second
	time.Sleep(delay)

	for {
		d := downloadJuliuszTree(&node)
		log.Print("Got tree")
		displayDirectory(&d, 0)
		hexStr := "6a323926ba8ce6082b9657b0ab48b41849a4d43a4efce34072b7c78ff7cdcb50"
		h, _ := hex.DecodeString(hexStr)
		var h2 [32]byte
		copy(h2[:], h[:32])
		//e := findEntry(h2, &d)
		log.Printf("The ROOT hash is : %x", computeHash(&d))
		time.Sleep(10000 * time.Second)
	}
}
