package main

import (
	"dfs/common"
	"log"
	"net"

	lru "github.com/hashicorp/golang-lru"
)

const clientName = "HTTP200JokesAreOK"

const MAX_CACHED_ENTRIES = 10

func main() {

	publicKey, privateKey, err := common.GenECDSAKeyPair()
	if err != nil {
		log.Fatal("Couldn't generate ECDSA key pair")
		return
	}

	formattedPublicKey := common.GetFormattedECDSAPublicKey(publicKey)

	juliuszAddresses, err := common.GetPeerAddresses(common.Juliusz)
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

	node := common.Node{clientName,
		privateKey,
		publicKey,
		formattedPublicKey,
		conn,
		bootstrapAddresses,
		make(map[uint32]chan []byte),
		cachedEntries,
	}

	// Start RPC server
	go common.RpcServer(&node)

	for _, addr := range node.BootstrapAddresses {
		hello, err := common.MakeHello(1, &node)
		if err != nil {
			log.Fatal(err)
		}

		if err == nil {
			log.Print("Sent hello!")
			node.Conn.WriteToUDP(hello, addr)
			continue
		}
	}

	go common.SendPeriodicHello(&node)
	go common.ReceiveIncomingMessages(&node)

	/*var delay time.Duration = 8 * time.Second
	time.Sleep(delay)

	juliuszRoot, _ := common.GetPeerRoot(common.Juliusz)
	d := common.RetrieveEntry(juliuszRoot, &node)
	common.DisplayDirectory(&d, 0)

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
	}*/

	for {
		/*time.Sleep(1 * time.Second)
		for _, e := range h {
			en := common.RetrieveEntry(e, &node)
			common.DisplayDirectory(&en, 0)
		}*/
	}
}
