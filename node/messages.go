package main

import (
	"encoding/binary"
)

var headerLength = 7
var extensionsLength = 4

func makeHello(id uint32, node *Node) ([]byte, error) {
	nameLength := len(node.name)
	packetLength := extensionsLength + nameLength
	h := make([]byte, headerLength+packetLength+signatureLength)
	binary.BigEndian.PutUint32(h[0:4], id)
	binary.BigEndian.PutUint16(h[5:headerLength], uint16(packetLength))
	copy(h[headerLength+extensionsLength:], []byte(node.name))
	sign, err := signECDSA(node.privateKey, h[:headerLength+packetLength])
	if err != nil {
		return nil, err
	}
	copy(h[headerLength+packetLength:], sign)
	return h, nil
}

func makeHelloReply(id uint32, node *Node) ([]byte, error) {
	nameLength := len(node.name)
	packetLength := extensionsLength + nameLength
	h := make([]byte, headerLength+packetLength+signatureLength)
	binary.BigEndian.PutUint32(h[0:4], id)
	h[4] = helloReplyType
	binary.BigEndian.PutUint16(h[5:headerLength], uint16(packetLength))
	copy(h[headerLength+extensionsLength:], []byte(node.name))
	sign, err := signECDSA(node.privateKey, h[:headerLength+packetLength])
	if err != nil {
		return nil, err
	}
	copy(h[headerLength+packetLength:], sign)
	return h, nil
}

func makePublicKey(id uint32, node *Node) ([]byte, error) {
	packetLength := publicKeyLength
	h := make([]byte, headerLength+packetLength+signatureLength)
	binary.BigEndian.PutUint32(h[0:4], id)
	h[4] = publicKeyType
	binary.BigEndian.PutUint16(h[5:headerLength], uint16(packetLength))
	copy(h[headerLength:], node.formattedPublicKey[:])
	sign, err := signECDSA(node.privateKey, h[:headerLength+packetLength])
	if err != nil {
		return nil, err
	}
	copy(h[headerLength+packetLength:], sign)
	return h, nil
}

func makePublicKeyReply(id uint32, node *Node) ([]byte, error) {
	packetLength := publicKeyLength
	h := make([]byte, headerLength+packetLength+signatureLength)
	binary.BigEndian.PutUint32(h[0:4], id)
	h[4] = publicKeyReplyType
	binary.BigEndian.PutUint16(h[5:headerLength], uint16(packetLength))
	copy(h[headerLength:], node.formattedPublicKey[:])
	sign, err := signECDSA(node.privateKey, h[:headerLength+packetLength])
	if err != nil {
		return nil, err
	}
	copy(h[headerLength+packetLength:], sign)
	return h, nil
}

func makeRoot(id uint32, hash [32]byte, node *Node) ([]byte, error) {
	packetLength := hashLength
	h := make([]byte, headerLength+packetLength+signatureLength)
	binary.BigEndian.PutUint32(h[0:4], id)
	h[4] = rootType
	binary.BigEndian.PutUint16(h[5:headerLength], uint16(packetLength))
	copy(h[headerLength:], hash[:])
	sign, err := signECDSA(node.privateKey, h[:headerLength+packetLength])
	if err != nil {
		return nil, err
	}
	copy(h[headerLength+packetLength:], sign)
	return h, nil
}

func makeRootReply(id uint32, hash [32]byte, node *Node) ([]byte, error) {
	packetLength := hashLength
	h := make([]byte, headerLength+packetLength+signatureLength)
	binary.BigEndian.PutUint32(h[0:4], id)
	h[4] = rootReplyType
	binary.BigEndian.PutUint16(h[5:headerLength], uint16(packetLength))
	copy(h[headerLength:], hash[:])
	sign, err := signECDSA(node.privateKey, h[:headerLength+packetLength])
	if err != nil {
		return nil, err
	}
	copy(h[headerLength+packetLength:], sign)
	return h, nil
}

func makeGetDatum(id uint32, hash [32]byte, node *Node) ([]byte, error) {
	packetLength := hashLength
	h := make([]byte, headerLength+packetLength+signatureLength)
	binary.BigEndian.PutUint32(h[0:4], id)
	h[4] = getDatumType
	binary.BigEndian.PutUint16(h[5:headerLength], uint16(packetLength))
	copy(h[headerLength:], hash[:])
	sign, err := signECDSA(node.privateKey, h[:headerLength+packetLength])
	if err != nil {
		return nil, err
	}
	copy(h[headerLength+packetLength:], sign)
	return h, nil
}

func makeError(id uint32, errorMessage string, node *Node) ([]byte, error) {
	errLength := len(errorMessage)
	packetLength := errLength
	h := make([]byte, headerLength+packetLength+signatureLength)
	binary.BigEndian.PutUint32(h[0:4], id)
	h[4] = errorType
	binary.BigEndian.PutUint16(h[5:headerLength], uint16(packetLength))
	copy(h[headerLength:], errorMessage)
	sign, err := signECDSA(node.privateKey, h[:headerLength+packetLength])
	if err != nil {
		return nil, err
	}
	copy(h[headerLength+packetLength:], sign)
	return h, nil
}
