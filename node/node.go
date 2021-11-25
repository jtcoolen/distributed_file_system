package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"log"
	"net"
	"time"

	lru "github.com/hashicorp/golang-lru"
)

type Node struct {
	name                 string
	privateKey           *ecdsa.PrivateKey
	publicKey            *ecdsa.PublicKey
	formattedPublicKey   [64]byte
	conn                 *net.UDPConn
	bootstrapAddresses   []*net.UDPAddr
	pendingPacketQueries map[uint32]chan []byte
	cachedEntries        *lru.ARCCache
}

var clientName = "HTTP200JokesAreOK"

const MAX_CACHED_ENTRIES = 100

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

func cache(entry *Entry, node *Node) {
	if entry.entryType == Chunk {
		node.cachedEntries.Add(entry.hash, *entry)
		return
	}
	for _, c := range entry.children {
		node.cachedEntries.Add(entry.hash, *entry)
		cache(c, node)
	}
}

func retrieveEntry(hash [32]byte, node *Node) Entry {
	root := Entry{Directory, "", hash, nil, nil}
	var currentEntry *Entry

	var id uint32 = 2 // TODO: global id variable?
	hashes := make([][32]byte, 0)
	hashes = append(hashes, hash)

	for len(hashes) != 0 {
		id++

		cachedEntry, ok := node.cachedEntries.Get(hashes[0])
		if ok {
			log.Printf("Using cached Entry(%x)", hashes[0])
			e := cachedEntry.(Entry)
			currentEntry = findEntry(hashes[0], &root)
			hashes = hashes[1:] // Remove processed hash
			*currentEntry = e
			continue
		}

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
			len := int(packetLength) - hashLength
			// TODO: chack hashes
			//copy(h[:], packet[headerLength:headerLength+hashLength])
			//currentEntry.hash = h
			currentEntry.data = make([]byte, len)
			copy(currentEntry.data, packet[headerLength+hashLength:headerLength+int(packetLength)])

		case 1: // Tree
			currentEntry.entryType = Tree
			len := int(packetLength) - 1 - hashLength
			for i := 0; i < len/32; i += 1 {
				copy(h[:], packet[headerLength+hashLength+1+i*32:headerLength+hashLength+1+i*32+32])
				hashes = append(hashes, h)
				currentEntry.children = append(currentEntry.children, &Entry{Chunk, "", h, nil, nil})
			}

		case 2: // Directory
			currentEntry.entryType = Directory
			len := int(packetLength) - 1 - hashLength
			for i := 0; i < len/64; i += 1 {
				copy(h[:], packet[headerLength+hashLength+1+32+i*64:headerLength+hashLength+1+i*64+32+32])
				name := packet[headerLength+hashLength+1+i*64 : headerLength+hashLength+1+i*64+32]
				hashes = append(hashes, h)
				currentEntry.children = append(currentEntry.children, &Entry{Directory, string(name), h, nil, nil})
			}
		}
	}
	cache(&root, node)
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

	cachedEntries, err := lru.NewARC(MAX_CACHED_ENTRIES)
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
		cachedEntries,
	}

	// Start RPC server
	go rpcServer(&node)

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

	juliuszRoot, _ := getPeerRoot(juliusz)
	d := retrieveEntry(juliuszRoot, &node)
	displayDirectory(&d, 0)

	hs := make([]string, 6)
	hs[0] = "409a750241dc70419744cb1e80e1bb6ba8b85f29d40c0c19f672e38526fee91f"
	hs[1] = "230729114233645b01024f325c0916b0673a17cd6ee76bf660f6b3363ad2214e"
	hs[2] = "a5249656c59c8a8480ca086cc0cb51f9c7de20a4938d78f5eaeeb9f41f13f161"
	hs[3] = "4f7dc682324d901ed0b947dd12ee1267d5fed846adc526772b2fd3f96f6eeffb"
	hs[4] = "9f02206417ee2ac837136c02759c48f8024d26c0ab2c69c3553229d65e0678b0"
	hs[5] = "8dbd2c084064473a16640235662d60083c64806a635ed67a79aa4d0b8a313dae"
	h := make([][32]byte, 6)
	var de [32]byte
	for i, e := range hs {
		des, _ := hex.DecodeString(e)
		copy(de[:], des)
		h[i] = de
	}

	for {
		time.Sleep(1 * time.Second)
		for _, e := range h {
			retrieveEntry(e, &node)
		}
	}
}
