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
	entry := FindEntryByPath(strings.Split(args.Path, "/"), &rootEntry)
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
	str, err := DisplayDirectoryFromPath(strings.Split(args.Path, "/"), &rootEntry)
	if err == nil {
		*reply = str
		return nil
	}
	return ErrNotFound
}
