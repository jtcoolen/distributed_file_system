package main

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

func displayDirectory(entry *Entry, level int) {
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
			displayDirectory(e, level+1)
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
	if entry.children == nil || len(entry.children) == 0 {
		return sha256.Sum256(entry.data)
	}
	concatHash := make([]byte, 32*len(entry.children))
	for i, c := range entry.children {
		h := computeHash(c)
		copy(concatHash[i*32:i*32+32], h[:])
	}
	return sha256.Sum256(concatHash)
}
