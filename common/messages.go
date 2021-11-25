package common

import (
	"encoding/binary"
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
