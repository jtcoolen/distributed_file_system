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
	concatHash := make([]byte, 1+32*len(entry.children))
	concatHash[0] = 1
	for _, c := range entry.children {
		node.cachedEntries.Add(entry.hash, *entry)
		cache(c, node)
	}
}

func downloadJuliuszTree(node *Node) Entry {
	juliuszRoot, _ := getPeerRoot(juliusz)

	root := Entry{Directory, "", juliuszRoot, nil, nil}
	var currentEntry *Entry

	var id uint32 = 2 // TODO: global id variable?
	hashes := make([][32]byte, 0)
	hashes = append(hashes, juliuszRoot)

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

	h := "0054a4e07856e972e4353eb282ab29998530a7dc226fd4a54d15ded149a5e4c01932aef84749a9a85f3b54b869d83d34c1ecb3755ffcbeb7f9576fe13ffc8a8ff94ab19abd547efe9d007d550ed1ed8e56836d031ad63490d1d27a2c97ff00e776df0efe8b7e9723ff006d699636a951e18cb4a24b6ad6307d82546c6be9f6d5cd2a54ab5319a6ca7e979f93d53d6ffea8a5fe5fe8b4a9fd3f7feaae2b385dd236a4540fa3bc3981b530547a7e9add274e352b54193bdee3c4f40a1f12ff007d6ff3ff00fdad1beffcaaaffcf5092223a46dae2d2a55a6f6bc10eda5bdc058da3d8d1a34dcebc752fc44f98439c258defecacdaffe169ffee3bf92a37bff008cd4bff61bff00f2591b6ef2dd6756ad27c80c76d2d748e31c2e1685bd76ef7d61fdebb01c795d1f877ffa7e9ff99fff00f1589a8fd547ff0070235c454ad8b5e3cca41bb8448f8563c2d49f56eeeef1c26930f96c9ea472548fe9fe73fc8a9bc2dff90bbff7aa7f350a70cfed0bdaf59c0f96c3b18018e395a563a7eea80b6e2ab27a074859fa3ffe0c7f98adcd3b9fb2b12b5b4cb5ab4ee3ca35cd5a6d6024380e4f0b65b4c0e802a1a77fe2ae3ff8ff0025a216a22bdd06b6daa12200692bc27f68b7fe75fd1b66ba4325c57baea3ff0080adfe42be75f1a7ff005154ff00205460a4924b485f291e523c2481e70992490249249024924ba141ea3fb14bcdb77a95993f5b59500fce57b044af11fd8cff00f53dcfff00ebff0055edc1654db4442620f44ee49026820f2a3b9a2daf6f5293c4b5ed20852a478528f19d46d9da6eab5ad9ed801d8f8587a8520cb8ddd0aeb3c6ff00fd46ff00f2ae6353fa5ab1fadc51c121a324af59f07e966cf48a7382e125793daffe3697f982f70d33ff002ba5fe40b512acb9a2400f8f7285d4f3bdae3f12a377d0dff329c707e4ad3288b1c24131d402553d42a7916cf82e30d8267956eafd4eff009eab2f5aff00c354ff0028fe4b2385d42b9ab72e3b8954c9f9525c7f7ae51f50b0dc0e1ca3a950e47447d4a86a7f545013ee81e73288f0a372044f5951b89039467851b9001cf54c4a7ebf643fc2ac0c4fb26948a6e9f75a05bc8490a4b0cbffd9"
	h2, _ := hex.DecodeString(h)
	log.Printf("Hash : %x", sha256.Sum256(h2))

	hh := "010f66bd528a6636215df02b1ca5b6a20d316ad1ae426755f1f5e6764fea19a862d6a8e671404ab77b1aa92123e3bbb14206742791369e78c7073d0e66009bb2a0b501558116621cddf17df185acbb583c6d30a9bb0e5ad42e3d8b5a5bddd20a9ff06847b92caeb7a9b23e3ff6828f8f87b32b2232539532baacab80d595d6f8ae0eb3042b0afa4808d96ad5a0f3a829757baa0d26c774ebbacc7ef2fd4d9aa66e93ccc06a681729b70c74092669fe21475d8eb609b0e883f8fbc53f8f6e1c7247ab4cae7dc168adb38fa3d2567abff79ea26716e71c9b6394ae790ddcb7224d0d7e08a69d77999f0b8e1d2ffe01f2b839d19deeb331cc2ef521d6ce5482d06c6a5476480b310f5d7857be4e1101351a3b95e27b332a55fab779fccd4bc076a61869a075505c2b4c240cb170d6f6c924ddbc7969e3d603e76dffc47a61750234dcb15db2dffb37ff719c4cd2a9a9f09da9a88907fb1d9395b5afac67c8cb3ff402a1924a1fa6d76d9e252e6efbf6a28c971297a4830c5a5bbf4d35f6a8f12087be"
	hh2, _ := hex.DecodeString(hh)
	log.Printf("Hash 2 : %x", sha256.Sum256(hh2))

	var delay time.Duration = 8 * time.Second
	time.Sleep(delay)

	d := downloadJuliuszTree(&node)
	log.Print("Got tree")
	displayDirectory(&d, 0)
	for {
		displayDirectory(&d, 0)
		time.Sleep(1 * time.Second)
	}
}
