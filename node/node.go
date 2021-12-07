package main

import (
	"crypto/sha256"
	"dfs/common"
	"log"
	"net"
	"os"
	"sync"

	lru "github.com/hashicorp/golang-lru"
)

var clientName = "hello"

const MAX_CACHED_ENTRIES = 100

const history = "The movement of humanity, arising as it does from innumerable arbitrary human wills, is continuous. To understand the laws of this continuous movement is the aim of history. But to arrive at these laws, resulting from the sum of all those human wills, man's mind postulates arbitrary and disconnected units. The first method of history is to take an arbitrarily selected series of continuous events and examine it apart from others, though there is and can be no beginning to any event, for one event always flows uninterruptedly from another.\nThe second method is to consider the actions of some one man- a king or a commander- as equivalent to the sum of many individual wills; whereas the sum of individual wills is never expressed by the activity of a single historic personage.\nHistorical science in its endeavor to draw nearer to truth continually takes smaller and smaller units for examination. But however small the units it takes, we feel that to take any unit disconnected from others, or to assume a beginning of any phenomenon, or to say that the will of many men is expressed by the actions of any one historic personage, is in itself false.\nIt needs no critical exertion to reduce utterly to dust any deductions drawn from history. It is merely necessary to select some larger or smaller unit as the subject of observation- as criticism has every right to do, seeing that whatever unit history observes must always be arbitrarily selected. Only by taking infinitesimally small units for observation (the differential of history, that is, the individual tendencies of men) and attaining to the art of integrating them (that is, finding the sum of these infinitesimals) can we hope to arrive at the laws of history."

var myFile = common.Entry{
	Type:     common.Chunk,
	Name:     "history.txt",
	Hash:     sha256.Sum256([]byte("")),
	Children: nil,
	Data:     []byte(history),
}

var myDir = common.Entry{
	Type:     common.Directory,
	Name:     "root",
	Hash:     sha256.Sum256([]byte("")),
	Children: make([]*common.Entry, 0),
	Data:     nil,
}

func main() {
	if len(os.Args) > 1 {
		clientName = os.Args[1]
		log.Printf("clientName: %s\n", clientName)
	}

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
		Port: 12355,
		IP:   net.IP{0, 0, 0, 0}, // listen to all addresses
	}

	conn, err := net.ListenUDP("udp", &addr) //TODO Minoo why this step?
	if err != nil {
		panic(err)
	}

	cachedEntries, err := lru.NewARC(MAX_CACHED_ENTRIES)
	if err != nil {
		panic(err)
	}

	myFile.Hash = common.ComputeHash(&myFile)
	myDir.Children = append(myDir.Children, &myFile)
	myDir.Hash = common.ComputeHash(&myDir)

	node := common.Node{
		Name:                 clientName,
		PrivateKey:           privateKey,
		PublicKey:            publicKey,
		FormattedPublicKey:   formattedPublicKey,
		Conn:                 conn,
		BootstrapAddresses:   bootstrapAddresses,
		PendingPacketQueries: make(map[uint32]chan []byte),
		CachedEntries:        cachedEntries,
		ExportedDirectory:    &myDir,
		Id:                   1,
		SessionKeys:          make(map[string]common.SessionKey),
	}
	log.Printf("My root hash is %x", common.ComputeHash(node.ExportedDirectory))
	log.Printf("Empty string hash is %x", sha256.Sum256([]byte("")))

	// Start RPC server
	go common.RpcServer(&node)

	for _, addr := range node.BootstrapAddresses {
		hello, err := common.MakeHello(common.NewId(&node), &node)
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

	// wait on itself
	func() {
		wg := sync.WaitGroup{}
		wg.Add(1)
		wg.Wait()
	}()
}
