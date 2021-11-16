package main

import (
	"encoding/binary"
)

var headerLength = 7
var extensionsLength = 4

func makeHello(id uint32, name string) []byte {
	nameLength := len(name)
	h := make([]byte, headerLength+extensionsLength+nameLength)
	binary.BigEndian.PutUint32(h[0:4], id)
	binary.BigEndian.PutUint16(h[5:7], uint16(extensionsLength)+uint16(nameLength))
	copy(h[headerLength+4:], name)
	return h
}

func makeHelloReply(id uint32, name string) []byte {
	nameLength := len(name)
	h := make([]byte, headerLength+extensionsLength+nameLength)
	binary.BigEndian.PutUint32(h[0:4], id)
	h[4] = helloReplyType
	binary.BigEndian.PutUint16(h[5:7], uint16(extensionsLength)+uint16(nameLength))
	copy(h[headerLength+4:], name)
	return h
}

func makePublicKey(id uint32, publicKey [64]byte) []byte {
	h := make([]byte, headerLength+publicKeyLength)
	binary.BigEndian.PutUint32(h[0:4], id)
	h[4] = publicKeyType
	copy(h[headerLength:], publicKey[:])
	return h
}

func makePublicKeyReply(id uint32) []byte {
	h := make([]byte, headerLength)
	binary.BigEndian.PutUint32(h[0:4], id)
	h[4] = makePublicKeyReplyType
	return h
}

func makeRoot(id uint32, hash []byte) []byte {
	h := make([]byte, headerLength+hashLength)
	binary.BigEndian.PutUint32(h[0:4], id)
	h[4] = rootType
	copy(h[headerLength:], hash)
	return h
}

func makeRootReply(id uint32, hash []byte) []byte {
	h := make([]byte, headerLength+hashLength)
	binary.BigEndian.PutUint32(h[0:4], id)
	h[4] = rootReplyType
	copy(h[headerLength:], hash)
	return h
}

func makeError(id uint32, err string) []byte {
	errLength := len(err)
	h := make([]byte, headerLength+errLength)
	binary.BigEndian.PutUint32(h[0:4], id)
	h[4] = errorType
	copy(h[headerLength:], err)
	return h
}
