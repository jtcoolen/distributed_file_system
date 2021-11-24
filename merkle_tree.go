package main

import (
	"crypto/sha256"
)

type MerkleNode struct {
	entry [32]byte
	left  *MerkleNode
	right *MerkleNode
}

func computeHash(node *MerkleNode) [32]byte {
	if node.right == nil {
		return node.left.entry
	}
	return sha256.Sum256(append(node.left.entry[:], node.right.entry[:]...))
}
