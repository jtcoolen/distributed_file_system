package main

import (
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
}

func displayDirectory(entry *Entry, level int) {
	tabs := strings.Repeat(" ", level)
	switch entry.entryType {
	case Chunk:
		fmt.Printf("%sChunk: %x\n", tabs, entry.hash)
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
