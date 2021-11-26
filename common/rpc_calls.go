package common

import (
	"log"
	"strings"
)

type RetrieveEntryByPathArgs struct {
	Peer string
	Path string
}

func (t *Node) RetrieveEntry(hash [32]byte, reply *Entry) error {
	*reply = RetrieveEntry(hash, t)
	return nil
}

func (t *Node) RetrieveEntryByPath(args *RetrieveEntryByPathArgs, reply *Entry) error {
	rootHash, err := GetPeerRoot(args.Peer)
	if err != nil {
		return err
	}
	rootEntry := RetrieveEntry(rootHash, t)
	s := strings.Split(args.Path, "/")
	if s[0] == "" {
		s = s[1:]
	}
	if s[len(s)-1] == "" {
		s = s[:len(s)-1]
	}
	entry := FindEntryByPath(s, &rootEntry)
	if entry != nil {
		*reply = *entry
		log.Print("OK")
	}
	log.Print("NOOOO")
	return nil
}

func (t *Node) DisplayDirectoryPath(args *RetrieveEntryByPathArgs, reply *string) error {
	rootHash, err := GetPeerRoot(args.Peer)
	if err != nil {
		return err
	}
	rootEntry := RetrieveEntry(rootHash, t)
	s := strings.Split(args.Path, "/")
	if s[0] == "" {
		s = s[1:]
	}
	if s[len(s)-1] == "" {
		s = s[:len(s)-1]
	}
	str, err := DisplayDirectoryFromPath(s, &rootEntry)
	if err == nil {
		*reply = str
		return nil
	}
	return ErrNotFound
}
