package common

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
)

const headerLength int = 7
const extensionsLength int = 4

func MakeHello(id uint32, node *Node) ([]byte, error) {
	nameLength := len(node.Name)
	packetLength := extensionsLength + nameLength
	h := make([]byte, headerLength+packetLength+SignatureLength)
	binary.BigEndian.PutUint32(h[0:4], id)
	binary.BigEndian.PutUint16(h[5:headerLength], uint16(packetLength))
	copy(h[headerLength+extensionsLength:], []byte(node.Name))
	sign, err := SignECDSA(node.PrivateKey, h[:headerLength+packetLength])
	if err != nil {
		return nil, err
	}
	copy(h[headerLength+packetLength:], sign)
	return h, nil
}

func MakeHelloReply(id uint32, node *Node) ([]byte, error) {
	nameLength := len(node.Name)
	packetLength := extensionsLength + nameLength
	h := make([]byte, headerLength+packetLength+SignatureLength)
	binary.BigEndian.PutUint32(h[0:4], id)
	h[4] = HelloReplyType
	binary.BigEndian.PutUint16(h[5:headerLength], uint16(packetLength))
	copy(h[headerLength+extensionsLength:], []byte(node.Name))
	sign, err := SignECDSA(node.PrivateKey, h[:headerLength+packetLength])
	if err != nil {
		return nil, err
	}
	copy(h[headerLength+packetLength:], sign)
	return h, nil
}

func MakePublicKey(id uint32, node *Node) ([]byte, error) {
	packetLength := PublicKeyLength
	h := make([]byte, headerLength+packetLength+SignatureLength)
	binary.BigEndian.PutUint32(h[0:4], id)
	h[4] = PublicKeyType
	binary.BigEndian.PutUint16(h[5:headerLength], uint16(packetLength))
	copy(h[headerLength:], node.FormattedPublicKey[:])
	sign, err := SignECDSA(node.PrivateKey, h[:headerLength+packetLength])
	if err != nil {
		return nil, err
	}
	copy(h[headerLength+packetLength:], sign)
	return h, nil
}

func makePublicKeyReply(id uint32, node *Node) ([]byte, error) {
	packetLength := PublicKeyLength
	h := make([]byte, headerLength+packetLength+SignatureLength)
	binary.BigEndian.PutUint32(h[0:4], id)
	h[4] = PublicKeyReplyType
	binary.BigEndian.PutUint16(h[5:headerLength], uint16(packetLength))
	copy(h[headerLength:], node.FormattedPublicKey[:])
	sign, err := SignECDSA(node.PrivateKey, h[:headerLength+packetLength])
	if err != nil {
		return nil, err
	}
	copy(h[headerLength+packetLength:], sign)
	return h, nil
}

func makeRoot(id uint32, hash [32]byte, node *Node) ([]byte, error) {
	packetLength := HashLength
	h := make([]byte, headerLength+packetLength+SignatureLength)
	binary.BigEndian.PutUint32(h[0:4], id)
	h[4] = RootType
	binary.BigEndian.PutUint16(h[5:headerLength], uint16(packetLength))
	copy(h[headerLength:], hash[:])
	sign, err := SignECDSA(node.PrivateKey, h[:headerLength+packetLength])
	if err != nil {
		return nil, err
	}
	copy(h[headerLength+packetLength:], sign)
	return h, nil
}

func makeRootReply(id uint32, hash [32]byte, node *Node) ([]byte, error) {
	packetLength := HashLength
	h := make([]byte, headerLength+packetLength+SignatureLength)
	binary.BigEndian.PutUint32(h[0:4], id)
	h[4] = RootReplyType
	binary.BigEndian.PutUint16(h[5:headerLength], uint16(packetLength))
	copy(h[headerLength:], hash[:])
	sign, err := SignECDSA(node.PrivateKey, h[:headerLength+packetLength])
	if err != nil {
		return nil, err
	}
	copy(h[headerLength+packetLength:], sign)
	return h, nil
}

func makeGetDatum(id uint32, hash [32]byte, node *Node) ([]byte, error) {
	packetLength := HashLength
	h := make([]byte, headerLength+packetLength+SignatureLength)
	binary.BigEndian.PutUint32(h[0:4], id)
	h[4] = GetDatumType
	binary.BigEndian.PutUint16(h[5:headerLength], uint16(packetLength))
	copy(h[headerLength:], hash[:])
	sign, err := SignECDSA(node.PrivateKey, h[:headerLength+packetLength])
	if err != nil {
		return nil, err
	}
	copy(h[headerLength+packetLength:], sign)
	return h, nil
}

func makeDatum(id uint32, hash [32]byte, node *Node) ([]byte, error) {

	entry := findEntry(hash, node.ExportedDirectory)
	if entry == nil {
		return nil, ErrNotFound
	}
	log.Printf("Entry type %d found %x ; hash %x", entry.Type, entry.Hash, hash)
	switch entry.Type {
	case Chunk:
		packetLength := HashLength + 1 + len(entry.Data)
		h := make([]byte, headerLength+packetLength+SignatureLength)
		binary.BigEndian.PutUint32(h[0:4], id)
		h[4] = DatumType
		binary.BigEndian.PutUint16(h[5:headerLength], uint16(packetLength))
		hash := make([]byte, HashLength)
		hh := ComputeHash(entry)
		copy(hash[:], hh[:])
		copy(h[headerLength:], hash)

		h[headerLength+HashLength] = 0
		copy(h[headerLength+HashLength+1:], entry.Data)

		sign, err := SignECDSA(node.PrivateKey, h[:headerLength+packetLength])
		if err != nil {
			return nil, err
		}
		log.Print("Message signed")
		copy(h[headerLength+packetLength:], sign)
		return h, nil

	case Tree:
		packetLength := HashLength + 1 + 32*len(entry.Children)
		h := make([]byte, headerLength+packetLength+SignatureLength)
		binary.BigEndian.PutUint32(h[0:4], id)
		h[4] = DatumType
		binary.BigEndian.PutUint16(h[5:headerLength], uint16(packetLength))
		hash := make([]byte, HashLength)
		hh := ComputeHash(entry)
		copy(hash[:], hh[:])
		copy(h[headerLength:], hash)

		h[headerLength+HashLength] = 1
		for i, c := range entry.Children {
			hc := ComputeHash(c)
			copy(h[headerLength+HashLength+1+i*32:headerLength+HashLength+1+i*32+32], hc[:])
		}

		sign, err := SignECDSA(node.PrivateKey, h[:headerLength+packetLength])
		if err != nil {
			return nil, err
		}
		log.Print("Message signed")
		copy(h[headerLength+packetLength:], sign)
		return h, nil

	case Directory:
		packetLength := HashLength + 1 + 64*len(entry.Children)
		h := make([]byte, headerLength+packetLength+SignatureLength)
		binary.BigEndian.PutUint32(h[0:4], id)
		h[4] = DatumType
		binary.BigEndian.PutUint16(h[5:headerLength], uint16(packetLength))
		hash := make([]byte, HashLength)
		hh := ComputeHash(entry)
		copy(hash[:], hh[:])
		copy(h[headerLength:], hash)
		h[headerLength+HashLength] = 2
		for i, c := range entry.Children {
			hc := ComputeHash(c)
			copy(h[headerLength+HashLength+1+i*64:headerLength+HashLength+1+i*64+32], []byte(c.Name))
			copy(h[headerLength+HashLength+1+i*64+32:headerLength+HashLength+1+i*64+64], hc[:])
		}
		sign, err := SignECDSA(node.PrivateKey, h[:headerLength+packetLength])
		if err != nil {
			return nil, err
		}
		log.Print("Message signed")
		copy(h[headerLength+packetLength:], sign)
		return h, nil
	}
	log.Print("ErrNoSuchType")
	return nil, ErrNoSuchType
}

func IPAndPort(ip net.UDPAddr) []byte {
	addr := make([]byte, 18)
	copy(addr[:], ip.IP)
	binary.BigEndian.PutUint16(addr[16:], uint16(ip.Port)) // TODO: return error if integer exceeds 2 bytes of capacity
	log.Printf("ADDR = %s ; len=%d", []byte(ip.IP), len(ip.IP))
	log.Print([]byte(ip.IP), addr)
	return addr
}

func makeNatTraversalRequest(id uint32, addr net.UDPAddr, node *Node) ([]byte, error) {
	dataLength := 18
	h := make([]byte, headerLength+dataLength+SignatureLength)
	//	binary.BigEndian.PutUint32(h[0:4], id)
	h[4] = NatTraversalRequestType
	binary.BigEndian.PutUint16(h[5:headerLength], uint16(dataLength))
	copy(h[headerLength:], IPAndPort(addr))
	sign, err := SignECDSA(node.PrivateKey, h[:headerLength+dataLength])
	if err != nil {
		return nil, err
	}
	copy(h[headerLength+dataLength:], sign)
	return h, nil
}

func makeNatTraversal(id uint32, addr net.UDPAddr, node *Node) ([]byte, error) {
	dataLength := 18
	h := make([]byte, headerLength+dataLength+SignatureLength)
	binary.BigEndian.PutUint32(h[0:4], id)
	h[4] = NatTraversalType
	binary.BigEndian.PutUint16(h[5:headerLength], uint16(dataLength))
	copy(h[headerLength:], IPAndPort(addr))
	sign, err := SignECDSA(node.PrivateKey, h[:headerLength+dataLength])
	if err != nil {
		return nil, err
	}
	copy(h[headerLength+dataLength:], sign)
	return h, nil
}

func makeError(id uint32, errorMessage string, node *Node) ([]byte, error) {
	errLength := len(errorMessage)
	packetLength := errLength
	h := make([]byte, headerLength+packetLength+SignatureLength)
	binary.BigEndian.PutUint32(h[0:4], id)
	h[4] = ErrorType
	binary.BigEndian.PutUint16(h[5:headerLength], uint16(packetLength))
	copy(h[headerLength:], errorMessage)
	sign, err := SignECDSA(node.PrivateKey, h[:headerLength+packetLength])
	if err != nil {
		return nil, err
	}
	copy(h[headerLength+packetLength:], sign)
	return h, nil
}

func makeDHKeyRequest(id uint32, node *Node) ([]byte, error) {
	packetLength := 0
	h := make([]byte, headerLength+packetLength+SignatureLength)
	binary.BigEndian.PutUint32(h[0:4], id)
	h[4] = DHKeyRequestType
	binary.BigEndian.PutUint16(h[5:headerLength], uint16(packetLength))
	sign, err := SignECDSA(node.PrivateKey, h[:headerLength+packetLength])
	if err != nil {
		return nil, err
	}
	copy(h[headerLength+packetLength:], sign)
	return h, nil
}

func MakeDHKey(id uint32, formattedPublicKey [2 * 66]byte, node *Node) ([]byte, error) {
	packetLength := 2 * 66
	h := make([]byte, headerLength+packetLength+SignatureLength)
	binary.BigEndian.PutUint32(h[0:4], id)
	h[4] = DHKeyType
	binary.BigEndian.PutUint16(h[5:headerLength], uint16(packetLength))
	copy(h[headerLength:], formattedPublicKey[:])
	sign, err := SignECDSA(node.PrivateKey, h[:headerLength+packetLength])
	if err != nil {
		return nil, err
	}
	copy(h[headerLength+packetLength:], sign)
	return h, nil
}

func makePacket(packet []byte, addr *net.UDPAddr, node *Node) ([]byte, error) {
	peer, err := FindPeerFromAddr(addr, node)
	if err != nil {
		RefreshRegisteredPeers(node)
		peer, err = FindPeerFromAddr(addr, node)
		if err != nil {
			return nil, err
		}
	}
	if k, found := node.SessionKeys[peer]; found {
		if !k.ready {
			log.Printf("K NOT READY")
			return nil, ErrMakePacket
		}
		fmt.Println(k)
		p := packet[headerLength : len(packet)-SignatureLength]
		h := make([]byte, len(p)+1)
		h[0] = packet[4]
		copy(h[1:], p)
		nonce := make([]byte, 12)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			log.Print(err)
		}
		var sig [32]byte
		copy(sig[:], packet[len(packet)-SignatureLength:])
		ciphertext, err := AES_256_GCM_encrypt(h, nonce, sig, k.sessionKey)
		if err != nil {
			return nil, err
		}

		encryptedPacketLength := len(ciphertext) + len(nonce)

		encryptedPacket := make([]byte, headerLength+encryptedPacketLength+SignatureLength)
		copy(encryptedPacket[:headerLength], packet[:headerLength])

		// update packet type & length
		encryptedPacket[4] = EncryptedPacketType
		binary.BigEndian.PutUint16(encryptedPacket[5:headerLength], uint16(encryptedPacketLength))

		// copy ciphertext
		copy(encryptedPacket[headerLength:], ciphertext)

		// append signature of plaintext at the end
		copy(encryptedPacket[len(encryptedPacket)-SignatureLength:], packet[len(packet)-SignatureLength:])
		log.Printf("Sig=%x, %x", sig, encryptedPacket[len(encryptedPacket)-SignatureLength:])

		// append nonce before signature
		copy(encryptedPacket[len(encryptedPacket)-len(nonce)-SignatureLength:len(encryptedPacket)-SignatureLength], nonce)

		log.Printf("Nonce=%x, %x", nonce, encryptedPacket[len(encryptedPacket)-len(nonce)-SignatureLength:len(encryptedPacket)-SignatureLength])
		return encryptedPacket, nil
	}

	return packet, nil
}

func decryptAndAuthenticatePacket(packet []byte, addr *net.UDPAddr, node *Node) ([]byte, error) {
	if packet[4] != EncryptedPacketType {
		return packet, nil
	}
	peer, err := FindPeerFromAddr(addr, node)
	if err != nil {
		RefreshRegisteredPeers(node)
		peer, err = FindPeerFromAddr(addr, node)
		if err != nil {
			return nil, err
		}
	}
	if k, found := node.SessionKeys[peer]; found {
		if !k.ready {
			log.Printf("K NOT READY")
			return nil, ErrMakePacket
		}
		body := packet[headerLength : len(packet)-nonceLength-SignatureLength]
		nonce := packet[len(packet)-nonceLength-SignatureLength : len(packet)-SignatureLength]
		signature := packet[len(packet)-SignatureLength:]
		var sig [32]byte
		copy(sig[:], signature)
		body, err = AES_256_GCM_decrypt(body, nonce, sig, k.sessionKey)
		if err != nil {
			log.Printf("Decryption failure! %s", err)
			return nil, ErrMakePacket
		}
		log.Printf("len b = %d", len(body))
		return body, nil
	}
	log.Printf("No session key found!")
	return nil, ErrMakePacket
}
