package common

import (
	"encoding/binary"
	"log"
	"net"
)

var headerLength = 7
var extensionsLength = 4

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
	return addr
}

func makeNatTraversalRequest(id uint32, addr net.UDPAddr, node *Node) ([]byte, error) {
	dataLength := 18
	h := make([]byte, headerLength+dataLength+SignatureLength)
	binary.BigEndian.PutUint32(h[0:4], id)
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
