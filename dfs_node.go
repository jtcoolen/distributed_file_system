package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"log"
	"net"
	"time"
)

var client_name = "test"

func genECDSAKeyPair() (*ecdsa.PublicKey, *ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return &privateKey.PublicKey, privateKey, nil
}

func formattedECDSAPublicKey(publicKey *ecdsa.PublicKey) []byte {
	formatted := make([]byte, 64)
	publicKey.X.FillBytes(formatted[:32])
	publicKey.Y.FillBytes(formatted[32:])
	return formatted
}

func processIncomingPacket(conn *net.UDPConn, addr *net.UDPAddr, packet []byte, pubKey []byte) {
	packetType := packet[4]
	id := binary.BigEndian.Uint32(packet[0:4])
	switch packetType {
	case helloType:
		log.Printf("Hello from %s", addr)
	case publicKeyType:
		log.Printf("Public Key from %s", addr)
		conn.WriteToUDP(makePublicKeyReply(id, pubKey), addr)
	case publicKeyReplyType:
		log.Printf("publicKeyReply from %s", addr)
	case helloReplyType:
		log.Printf("HelloReply from %s", addr)
	case errorType:
		log.Printf("Error: %s from %s", string(packet[headerLength:]), addr)
	default:
		log.Printf("Packet type=%d from %s", packetType, addr)

	}
}

func sendPeriodicHello(conn *net.UDPConn, addresses [][]byte, publicKey []byte) {
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

func receiveIncomingMessages(connection *net.UDPConn, pubKey []byte) {
	for {
		buffer := make([]byte, 1024)
		n, remoteAddr, err := 0, new(net.UDPAddr), error(nil)
		for err == nil {
			n, remoteAddr, err = connection.ReadFromUDP(buffer)
			go processIncomingPacket(connection, remoteAddr, buffer[:n], pubKey)
		}
	}
}

func main() {

	publicKey, _, err := genECDSAKeyPair()
	if err != nil {
		log.Fatal("Couldn't generate ECDSA key pair")
		return
	}

	formattedPublicKey := formattedECDSAPublicKey(publicKey)

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

	go sendPeriodicHello(connection, juliuszAddresses, formattedPublicKey)
	// for i := 0; i < runtime.NumCPU(); i++
	go receiveIncomingMessages(connection, formattedPublicKey)

	for {
	}
}
