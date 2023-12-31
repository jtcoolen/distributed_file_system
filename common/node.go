package common

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	lru "github.com/hashicorp/golang-lru"
)

type SessionKey struct {
	keyPair    *ECDHKeyPair
	sessionKey [sha256.Size]byte
	ready      bool
}

type PeerInfo struct {
	addresses []*net.UDPAddr
	publicKey [64]byte
	//rootHash  [32]byte
}

type Node struct {
	Name                 string
	Port                 int
	PrivateKey           *ecdsa.PrivateKey
	PublicKey            *ecdsa.PublicKey
	FormattedPublicKey   [64]byte
	Conn                 *net.UDPConn
	BootstrapAddresses   []*net.UDPAddr
	PendingPacketQueries map[uint32]chan []byte
	CachedEntries        *lru.ARCCache
	ExportedDirectory    *Entry
	Id                   uint32
	// Maps a peer's name with an ECDH session key:
	SessionKeys     map[string]SessionKey
	RegisteredPeers map[string]*PeerInfo
}

func RefreshRegisteredPeers(node *Node) {
	peers, err := GetPeers()
	if err != nil {
		return
	}

	for _, p := range peers {
		peerName := string(p)
		delete(node.RegisteredPeers, peerName)
		node.RegisteredPeers[peerName] = &PeerInfo{addresses: nil, publicKey: [64]byte{}}
		node.RegisteredPeers[peerName].addresses = make([]*net.UDPAddr, 10)
		addrs, err := GetPeerAddresses(peerName)
		if err != nil {
			return
		}
		for _, a := range addrs {
			log.Printf("Addr = %s", string(a))
			dest, err := net.ResolveUDPAddr("udp", string(a))
			if err != nil {
				continue
			}
			node.RegisteredPeers[peerName].addresses = append(node.RegisteredPeers[peerName].addresses, dest)
		}
		key, err := GetPeerKey(peerName)
		if err != nil {
			continue
		}
		var pk [64]byte
		copy(pk[:], key)
		node.RegisteredPeers[peerName].publicKey = pk
	}
}

func FindPeerFromAddr(addr *net.UDPAddr, node *Node) (string, *PeerInfo, error) {
	for peerName, peerInfo := range node.RegisteredPeers {
		for _, pAddr := range peerInfo.addresses {
			if pAddr != nil {
				if addr.IP.Equal(pAddr.IP) && addr.Port == pAddr.Port {
					return peerName, peerInfo, nil
				}
			}
		}
	}
	return "", nil, ErrNotFound
}

func NewId(node *Node) uint32 {
	var id uint32
	if node.Id != 0 {
		id = node.Id
		node.Id++
	} else {
		id = 1
		node.Id = 2
	}

	return id
}

func resolve(id uint32, packet []byte, node *Node) {
	if node.PendingPacketQueries[id] != nil {
		node.PendingPacketQueries[id] <- packet // broadcast
	}
}

func processIncomingPacket(node *Node, addr *net.UDPAddr, packet []byte) {
	packetSigned := false
	id := binary.BigEndian.Uint32(packet[0:4])
	packetType := packet[4]
	packetLength := binary.BigEndian.Uint16(packet[5:headerLength])
	log.Printf("packetLen=%d , len(packet)= %d , len(packet)-headerLength=%d", packetLength, len(packet), len(packet)-headerLength)
	log.Printf("packet type=%d", packetType)

	// TODO: check packet size (prevent buffer overflows from occurring)
	// Special case: peer does not have a public key:
	if !(packetType == 1 && packetLength == 0) {
		if len(packet)-int(headerLength) != int(packetLength) {
			if len(packet)-headerLength != int(packetLength)+SignatureLength {
				log.Print("Discarded incomming message: wrong size", len(packet)-int(headerLength) != int(packetLength),
					(len(packet)-headerLength != int(packetLength)+SignatureLength))
				reply, err := makeError(id, "wrong size", node)
				if err == nil {
					node.Conn.WriteToUDP(reply, addr)
					return
				}
				return
			}
		}
	}

	if packetType == EncryptedPacketType {
		body, err := decryptAndAuthenticatePacket(packet, addr, node)
		if err != nil {
			log.Printf("Decryption error: %s: aborting", err)
			return
		}
		log.Printf("len body %d", len(body))

		// Retrieve packet type
		pType := body[0]
		body = body[1:]

		log.Printf("Successful decryption!")

		p := make([]byte, headerLength+len(body)+SignatureLength)
		copy(p, packet[:headerLength])
		p[4] = pType
		binary.BigEndian.PutUint16(p[5:headerLength], uint16(len(body)))
		copy(p[headerLength:], body)
		copy(p[headerLength+len(body):], packet[len(packet)-SignatureLength:])
		// update packet length
		packetLength = binary.BigEndian.Uint16(p[5:headerLength])
		log.Printf("packet len=%d", packetLength)
		//log.Printf("packet len2=%d", packetLength-SignatureLength-nonceLength-1-uint16(headerLength))
		packet = p
		packetType = pType
	}

	if len(packet)-headerLength == int(packetLength)+SignatureLength {
		var sig [SignatureLength]byte
		copy(sig[:], packet[headerLength+int(packetLength):])
		_, info, err := FindPeerFromAddr(addr, node)
		if err != nil {
			RefreshRegisteredPeers(node)
			_, info, err = FindPeerFromAddr(addr, node)
			if err != nil {
				return
			}
		}
		log.Printf("PK=%x", info.publicKey)
		log.Printf("sig=%x", sig)
		log.Printf("packet=%x", packet[:headerLength+int(packetLength)])
		if !VerifyECDSASignature(info.publicKey, sig, packet[:headerLength+int(packetLength)]) {
			log.Print("Wrong signature")
			return
		}
		log.Print("Good signature")
		packetSigned = true
	}

	switch packetType {
	case HelloType:
		log.Printf("Hello from %s", addr)
		reply, err := MakeHelloReply(id, node)
		if err == nil {
			node.Conn.WriteToUDP(reply, addr)
			break
		}
		log.Printf("%s", err)

	case HelloReplyType:
		log.Printf("HelloReply from %s with id=%d", addr, binary.BigEndian.Uint32(packet[0:4]))

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
		reply, err := makeRootReply(id, node.ExportedDirectory.Hash, node)
		if err == nil {
			node.Conn.WriteToUDP(reply, addr)
			break
		}
		log.Printf("%s", err)

	case RootReplyType:
		//log.Printf("RootReply from %s", addr)

	case GetDatumType:
		log.Printf("GetDatum from %s with id %d", addr, id)
		var h [32]byte
		copy(h[:], packet[headerLength:headerLength+HashLength])
		reply, err := makeDatum(id, h, node)
		if err != nil {
			log.Printf("Datum initialization failure")
			break
		}
		reply, err = makePacket(reply, addr, node)
		if err != nil {
			log.Print(err)
			return
		}

		if err == nil {
			node.Conn.WriteToUDP(reply, addr)
			log.Printf("Replied to getDatum with id=%d to address %s", id, addr)
			break
		}
		log.Printf("%s", err)

	case DatumType:
		log.Printf("Datum(%x) from %s with id %d", packet[headerLength:headerLength+int(packetLength)], addr, id)

	case NoDatumType:
		log.Printf("NoDatum(%x) from %s", packet[headerLength:headerLength+int(packetLength)], addr)

	case NatTraversalType:
		log.Printf("NatTraversal from %s", addr)
		var ip net.IP = packet[headerLength : headerLength+16]
		port := binary.BigEndian.Uint16(packet[headerLength+16 : headerLength+16+2])
		dst, err := net.ResolveUDPAddr("udp", fmt.Sprintf("[%s]:%d", ip, port))
		if err != nil {
			log.Printf("OOOPSS cannot resolve %s: %s", fmt.Sprintf("[%s]:%d", ip, port), err.Error())
			break
		}
		log.Printf("Port is: %d", port)
		hello, err := MakeHello(NewId(node), node)
		if err == nil {
			node.Conn.WriteToUDP(hello, dst)
		}

	case ErrorType:
		log.Printf("Error: %s from %s", string(packet[headerLength:headerLength+int(packetLength)]), addr)

	case DHKeyRequestType:
		if !packetSigned {
			return
		}
		log.Printf("DHKeyRequest from %s", addr)
		keys, err := GenKeyPair()
		if err != nil {
			log.Printf("Could not generate key pair: %s: aborting", err)
			break
		}
		dhkey, err := MakeDHKey(NewId(node), GetFormattedECDHKey(keys.PublicKeyX, keys.PublicKeyY), node)
		if err == nil {
			node.Conn.WriteToUDP(dhkey, addr)

			peer, _, err := FindPeerFromAddr(addr, node)
			if err != nil {
				RefreshRegisteredPeers(node)
				peer, _, err = FindPeerFromAddr(addr, node)
				if err != nil {
					return
				}
			}
			delete(node.SessionKeys, peer)
			var s [sha256.Size]byte
			node.SessionKeys[peer] = SessionKey{keyPair: keys, sessionKey: s, ready: false}
		}

	case DHKeyType:
		if !packetSigned {
			return
		}
		log.Printf("DHKey from %s", addr)
		var formattedPublicKey [2 * 66]byte
		copy(formattedPublicKey[:], packet[headerLength:])
		RefreshRegisteredPeers(node)
		peer, _, err := FindPeerFromAddr(addr, node)
		if err != nil {
			log.Printf("Error FindPeerFromAddr !!!!!! %s", err)
			delete(node.SessionKeys, peer)
			return
		}
		if k, found := node.SessionKeys[peer]; found {
			log.Printf("OK formatted pubkey=%x", formattedPublicKey)
			key, err := GenSessionKey(formattedPublicKey, k.keyPair.PrivateKey)
			if err != nil {
				log.Printf("Error GenKey !!!!!! %s", err)
				delete(node.SessionKeys, peer)
				break
			}
			log.Printf("SessionKey=%x", key)
			k.sessionKey = key
			k.ready = true
			node.SessionKeys[peer] = k
		}

	default:
		log.Printf("Packet type=%d from %s", packetType, addr)
	}
	resolve(id, packet[:headerLength+int(packetLength)], node)
}

func SendPeriodicHello(node *Node) {
	for {
		for i, s := range node.SessionKeys {
			log.Printf("SessionKey(%s)=%x", i, s.sessionKey)
			log.Printf("privk=%x, pubk=(%d, %d)", s.keyPair.PrivateKey, s.keyPair.PublicKeyX, s.keyPair.PublicKeyY)
		}
		time.Sleep(HelloPeriod)
		for _, addr := range node.BootstrapAddresses {
			hello, err := MakeHello(NewId(node), node)
			if err == nil {
				node.Conn.WriteToUDP(hello, addr)
				continue
			}
			log.Printf("%s", err)
		}
		log.Printf("Incoming Messages Table Length = %d", len(node.PendingPacketQueries))
	}
}

func ReceiveIncomingMessages(node *Node) {
	for {
		buffer := make([]byte, 8192) // TODO: be careful when parsing
		n, remoteAddr, err := 0, new(net.UDPAddr), error(nil)
		for err == nil {
			n, remoteAddr, err = node.Conn.ReadFromUDP(buffer)
			if n > headerLength {
				go processIncomingPacket(node, remoteAddr, buffer[:n])
			}
		}
	}
}

func waitPacket(id uint32, packet []byte, node *Node, addr *net.UDPAddr) []byte { // TODO: return error after max retries
	var delay time.Duration = 200 * time.Millisecond
	limit := time.After(delay)
	stopAt := time.After(10 * time.Second)

	if node.PendingPacketQueries[id] == nil {
		node.PendingPacketQueries[id] = make(chan []byte)
	}

	v := node.PendingPacketQueries[id]

	for {
		select {
		case out := <-v:
			defer delete(node.PendingPacketQueries, id)
			return out

		case <-stopAt:
			log.Print("Timeout reached")
			defer delete(node.PendingPacketQueries, id)
			return nil

		case <-limit:
			log.Print("Limit reached")
			_, err := node.Conn.WriteToUDP(packet, addr)
			if err != nil {
				log.Print(err)
				return nil
			}
			delay = delay * delay
			limit = time.After(delay)
		}
	}
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

func ContactNodeBehindAddr(addrs []*net.UDPAddr, node *Node) error {
	for _, dest := range addrs {

		log.Printf("Got addr = %s", dest.String())
		log.Printf("Got addr = %s", dest.Network())
		id := NewId(node)
		hello, err := MakeHello(id, node)
		if err != nil {
			return err
		}

		_, err = node.Conn.WriteToUDP(hello, dest)
		if err != nil {
			return err
		}

		p := waitPacket(id, hello, node, dest)
		if p != nil {
			log.Print("NOOPE")
			return nil
		}
		// Timeout reached
		log.Printf("cannot contact addr %s", dest.Network())

		for _, a := range node.BootstrapAddresses {
			id := NewId(node)
			hello, err = makeNatTraversalRequest(id, *dest, node)
			if err == nil {
				_, err = node.Conn.WriteToUDP(hello, a)
				if err != nil {
					return err
				}
				continue
			}
		}
		log.Printf("Sent nat traversal request to Juliusz's peer")
		time.Sleep(1 * time.Second)

		id = NewId(node)
		hello, err = MakeHello(id, node)
		if err == nil {
			_, err = node.Conn.WriteToUDP(hello, dest)
			if err != nil {
				return err
			}
			log.Printf("Sent hello to %s", dest)
			continue
		}
	}
	return nil
}

func ContactNodeBehindNat(peer string, node *Node) error {
	addr, err := GetPeerAddresses(peer)
	if err != nil {
		log.Printf("cannot retrieve peer %s addresses: %s", peer, err.Error())
		return fmt.Errorf("cannot retrieve peer %s addresses: %s", peer, err.Error())
	}
	addrs := make([]*net.UDPAddr, 0)
	for _, a := range addr {
		log.Printf("Addr = %s", string(a))
		dest, err := net.ResolveUDPAddr("udp", string(a))
		if err != nil {
			return err
		}
		addrs = append(addrs, dest)
	}

	return ContactNodeBehindAddr(addrs, node)
}

func RetrieveEntry(hash [32]byte, peer string, addr *net.UDPAddr, node *Node) (*Entry, error) {
	root := &Entry{Directory, "", hash, nil, nil}
	var currentEntry *Entry

	hashes := make([][32]byte, 0)
	hashes = append(hashes, hash)

	for len(hashes) != 0 {
		id := NewId(node)
		cachedEntry, ok := node.CachedEntries.Get(hashes[0])
		if ok {
			log.Printf("Using cached Entry(%x)", hashes[0])
			e := cachedEntry.(Entry)
			currentEntry = findEntry(hashes[0], root)
			hashes = hashes[1:] // Remove processed hash
			*currentEntry = e
			continue
		}

		datum, err := makeGetDatum(id, hashes[0], node)
		if err != nil {
			log.Print(err)
			return nil, ErrNotFound
		}

		datum, err = makePacket(datum, addr, node)
		if err != nil {
			log.Print(err)
			return nil, ErrNotFound
		}

		_, err = node.Conn.WriteToUDP(datum, addr)
		if err != nil {
			log.Print(err)
			return nil, ErrNotFound
		}
		log.Printf("Sent getDatum(%x) with id=%d to address %s", hashes[0], id, addr)

		packet := waitPacket(id, datum, node, addr) // TODO: check if packet is valid
		if packet == nil {
			if ContactNodeBehindNat(peer, node) != nil {
				return nil, ErrNotFound // TODO: return error
			}
		}
		if len(packet) == 0 {
			log.Print("Got packet of length 0")
			return nil, ErrNotFound
		}
		if packet[4] == NoDatumType {
			log.Print("No Datum!")
			return nil, ErrNotFound // Return error
		}

		currentEntry = findEntry(hashes[0], root)

		packetLength := binary.BigEndian.Uint16(packet[5:headerLength])

		var pHash [32]byte
		copy(pHash[:], packet[headerLength:headerLength+HashLength])
		if pHash != sha256.Sum256(packet[headerLength+HashLength:headerLength+int(packetLength)]) {
			log.Printf("Hash Mismatch")
			return nil, ErrHashMismatch
		}

		hashes = hashes[1:] // Remove processed hash

		kind := packet[headerLength+HashLength]
		var h [32]byte

		switch kind {
		case 0: // Chunk
			currentEntry.Type = Chunk
			len := int(packetLength) - HashLength - 1
			currentEntry.Data = make([]byte, len)
			copy(currentEntry.Data, packet[headerLength+HashLength+1:headerLength+int(packetLength)])

		case 1: // Tree
			currentEntry.Type = Tree
			len := int(packetLength) - 1 - HashLength
			for i := 0; i < len/32; i += 1 {
				copy(h[:], packet[headerLength+HashLength+1+i*32:headerLength+HashLength+1+i*32+32])
				hashes = append(hashes, h)
				newChunk := Entry{Chunk, "", h, nil, nil}
				currentEntry.Children = append(currentEntry.Children, &newChunk)
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
				newDir := Entry{Directory, string(name), h, nil, nil}
				currentEntry.Children = append(currentEntry.Children, &newDir)
			}
		}
	}
	log.Printf("Downloaded Entry(%x)", currentEntry.Hash)
	cache(root, node)
	return root, nil
}
