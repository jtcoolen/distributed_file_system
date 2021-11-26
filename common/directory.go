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
	Type     EntryType
	Name     string
	Hash     [32]byte
	Children []*Entry
	Data     []byte
}

func DisplayDirectory(entry *Entry, level int) {
	tabs := strings.Repeat(" ", level)
	switch entry.Type {
	case Chunk:
		fmt.Printf("%sChunk len = %d : data = %x\n", tabs, len(entry.Data), entry.Data)
	case Tree:
		fmt.Printf("%sTree %s: %x\n", tabs, entry.Name, entry.Hash)
	case Directory:
		fmt.Printf("%sDirectory %s: %x\n", tabs, entry.Name, entry.Hash)
	}
	if entry.Children != nil {
		for _, e := range entry.Children {
			DisplayDirectory(e, level+1)
		}
	}
}

func findEntry(hash [32]byte, dir *Entry) *Entry {
	if dir.Hash == hash {
		return dir
	}
	for _, c := range dir.Children {
		e := findEntry(hash, c)
		if e != nil {
			return e
		}
	}
	return nil
}

func computeHash(entry *Entry) [32]byte {
	switch entry.Type {
	case Chunk:
		concatHash := make([]byte, 1+len(entry.Data))
		concatHash[0] = 0
		copy(concatHash[1:], entry.Data)
		return sha256.Sum256(concatHash)
	case Tree:
		concatHash := make([]byte, 1+32*len(entry.Children))
		concatHash[0] = 1
		for i, c := range entry.Children {
			h := computeHash(c)
			copy(concatHash[1+i*32:1+i*32+32], h[:])
		}
		return sha256.Sum256(concatHash)
	case Directory:
		concatHash := make([]byte, 1+64*len(entry.Children))
		concatHash[0] = 2
		for i, c := range entry.Children {
			h := computeHash(c)
			copy(concatHash[1+i*64:1+i*64+32], []byte(c.Name))
			copy(concatHash[1+i*64+32:1+i*64+64], h[:])
		}
		return sha256.Sum256(concatHash)
	}
	var h [32]byte
	return h
}
