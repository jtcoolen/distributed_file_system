package common

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

type EntryType int

const (
	Chunk EntryType = iota
	Tree
	Directory
)

type Entry struct {
	entryType EntryType
	name      string
	hash      [32]byte
	children  []*Entry
	data      []byte
}

func DisplayDirectory(entry *Entry, level int) {
	tabs := strings.Repeat(" ", level)
	switch entry.entryType {
	case Chunk:
		fmt.Printf("%sChunk len = %d: %x, computed hash: %x\n", tabs, len(entry.data), entry.hash, sha256.Sum256(entry.data))
	case Tree:
		fmt.Printf("%sTree %s: %x\n", tabs, entry.name, entry.hash)
	case Directory:
		fmt.Printf("%sDirectory %s: %x\n", tabs, entry.name, entry.hash)
	}
	if entry.children != nil {
		for _, e := range entry.children {
			DisplayDirectory(e, level+1)
		}
	}
}

func findEntry(hash [32]byte, dir *Entry) *Entry {
	if dir.hash == hash {
		return dir
	}
	for _, c := range dir.children {
		e := findEntry(hash, c)
		if e != nil {
			return e
		}
	}
	return nil
}

func computeHash(entry *Entry) [32]byte {
	if entry.entryType == Chunk {
		return sha256.Sum256(entry.data)
	}
	switch entry.entryType {
	case Tree:
		concatHash := make([]byte, 1+32*len(entry.children))
		concatHash[0] = 1
		for i, c := range entry.children {
			h := computeHash(c)
			copy(concatHash[1+i*32:1+i*32+32], h[:])
		}
		return sha256.Sum256(concatHash)
	case Directory:
		concatHash := make([]byte, 1+64*len(entry.children))
		concatHash[0] = 2
		for i, c := range entry.children {
			h := computeHash(c)
			copy(concatHash[1+i*64:1+i*64+32], []byte(c.name))
			copy(concatHash[1+i*64+32:1+i*64+64], h[:])
		}
		return sha256.Sum256(concatHash)
	}
	var h [32]byte
	return h
}
