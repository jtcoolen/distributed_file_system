package common

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"log"
	"net"
	"time"

	lru "github.com/hashicorp/golang-lru"
)

type Node struct {
	Name                 string
	PrivateKey           *ecdsa.PrivateKey
	PublicKey            *ecdsa.PublicKey
	FormattedPublicKey   [64]byte
	Conn                 *net.UDPConn
	BootstrapAddresses   []*net.UDPAddr
	PendingPacketQueries map[uint32]chan []byte
	CachedEntries        *lru.ARCCache
	ExportedDirectory    *Entry
}

func processIncomingPacket(node *Node, addr *net.UDPAddr, packet []byte) {
	id := binary.BigEndian.Uint32(packet[0:4])
	packetType := packet[4]
	packetLength := binary.BigEndian.Uint16(packet[5:headerLength])

	switch packetType {
	case HelloType:
		log.Printf("Hello from %s", addr)

	case HelloReplyType:
		log.Printf("HelloReply from %s", addr)

	case PublicKeyType:
		log.Printf("Public Key from %s", addr)
		reply, err := makePublicKeyReply(id, node)
		if err == nil {
			node.Conn.WriteToUDP(reply, addr)
			break
		}
		log.Printf("%s", err)

	case PublicKeyReplyType:
		log.Printf("publicKeyReply(%x) from %s", packet[headerLength:headerLength+int(packetLength)], addr)

	case RootType:
		log.Printf("Root(%x) from %s", packet[headerLength:headerLength+int(packetLength)], addr)
		reply, err := makeRootReply(id, sha256.Sum256([]byte("")), node)
		if err == nil {
			node.Conn.WriteToUDP(reply, addr)
			break
		}
		log.Printf("%s", err)

	case RootReplyType:
		//log.Printf("RootReply from %s", addr)

	case GetDatumType:
		//log.Printf("GetDatum from %s", addr)

	case DatumType:
		//log.Printf("Datum(%x) from %s with id %d", packet[headerLength:headerLength+int(packetLength)], addr, id)
		if node.PendingPacketQueries[id] != nil {
			node.PendingPacketQueries[id] <- packet[:headerLength+int(packetLength)]
		}

	case NoDatumType:
		//log.Printf("NoDatum(%x) from %s", packet[headerLength:headerLength+int(packetLength)], addr)
		if node.PendingPacketQueries[id] != nil {
			node.PendingPacketQueries[id] <- packet[:headerLength+int(packetLength)]
		}

	case ErrorType:
		log.Printf("Error: %s from %s", string(packet[headerLength:headerLength+int(packetLength)]), addr)

	default:
		log.Printf("Packet type=%d from %s", packetType, addr)
	}
}

func SendPeriodicHello(node *Node) {
	i := 0
	for {
		time.Sleep(HelloPeriod)
		for _, addr := range node.BootstrapAddresses {
			hello, err := MakeHello(1, node)
			if err == nil {
				node.Conn.WriteToUDP(hello, addr)
				continue
			}
			log.Printf("%s", err)
		}
		log.Printf("Incoming Messages Table Length = %d", len(node.PendingPacketQueries))
		i++
	}
}

func ReceiveIncomingMessages(node *Node) {
	for {
		buffer := make([]byte, 8192) // TODO: be careful when parsing
		n, remoteAddr, err := 0, new(net.UDPAddr), error(nil)
		for err == nil {
			n, remoteAddr, err = node.Conn.ReadFromUDP(buffer)
			go processIncomingPacket(node, remoteAddr, buffer[:n])
		}
	}
}

func waitPacket(id uint32, packet []byte, node *Node) []byte { // TODO: return error after max retries
	var delay time.Duration = 200000000
	limit := time.After(delay)

	var v chan []byte = node.PendingPacketQueries[id]

	if v != nil {
		defer delete(node.PendingPacketQueries, id)

		for {
			select {
			case out := <-v:
				return out

			case <-limit:
				_, err := node.Conn.WriteToUDP(packet, node.BootstrapAddresses[0])
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
	if entry.Type == Chunk {
		e := *entry
		node.CachedEntries.Add(entry.Hash, e)
		return
	}
	for _, c := range entry.Children {
		e := *entry
		node.CachedEntries.Add(entry.Hash, e)
		cache(c, node)
	}
}

func RetrieveEntry(hash [32]byte, node *Node) Entry {
	root := Entry{Directory, "", hash, nil, nil}
	var currentEntry *Entry

	var id uint32 = 2 // TODO: global id variable?
	hashes := make([][32]byte, 0)
	hashes = append(hashes, hash)

	for len(hashes) != 0 {
		id++

		cachedEntry, ok := node.CachedEntries.Get(hashes[0])
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

		node.PendingPacketQueries[id] = make(chan []byte) // TODO: check if there's already a pending query
		_, err = node.Conn.WriteToUDP(datum, node.BootstrapAddresses[0])
		if err != nil {
			log.Fatal(err)
		}

		packet := waitPacket(id, datum, node) // TODO: check if packet is valid
		if packet[4] == NoDatumType {
			log.Print("No Datum!")
			return root
		}

		currentEntry = findEntry(hashes[0], &root)

		hashes = hashes[1:] // Remove processed hash

		packetLength := binary.BigEndian.Uint16(packet[5:headerLength])
		// TODO: check if announced packet size is correct, or detect if a datagram contains multiple messages

		kind := packet[headerLength+HashLength]
		var h [32]byte

		switch kind {
		case 0: // Chunk
			currentEntry.Type = Chunk
			len := int(packetLength) - HashLength - 1
			// TODO: check hashes
			currentEntry.Data = make([]byte, len)
			copy(currentEntry.Data, packet[headerLength+HashLength+1:headerLength+int(packetLength)])

		case 1: // Tree
			currentEntry.Type = Tree
			len := int(packetLength) - 1 - HashLength
			for i := 0; i < len/32; i += 1 {
				copy(h[:], packet[headerLength+HashLength+1+i*32:headerLength+HashLength+1+i*32+32])
				hashes = append(hashes, h)
				currentEntry.Children = append(currentEntry.Children, &Entry{Chunk, "", h, nil, nil})
			}

		case 2: // Directory
			currentEntry.Type = Directory
			len := int(packetLength) - 1 - HashLength
			for i := 0; i < len/64; i += 1 {
				copy(h[:], packet[headerLength+HashLength+1+32+i*64:headerLength+HashLength+1+i*64+32+32])
				name := packet[headerLength+HashLength+1+i*64 : headerLength+HashLength+1+i*64+32]
				var b [1]byte
				name = bytes.Split(name, b[:])[0] // TODO: might be buggy
				hashes = append(hashes, h)
				currentEntry.Children = append(currentEntry.Children, &Entry{Directory, string(name), h, nil, nil})
			}
		}
	}
	log.Printf("Downloaded Entry(%x)", currentEntry.Hash)
	cache(&root, node)
	return root
}
