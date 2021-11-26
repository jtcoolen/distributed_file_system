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
		log.Print("NOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO")
		return err
	}
	rootEntry := RetrieveEntry(rootHash, t)
	//DisplayDirectory(&rootEntry, 0)
	entry := FindEntryByPath(strings.Split(args.Path, "/"), &rootEntry)
	if entry != nil {
		log.Print("OK!!!!!")
		*reply = *entry
	}
	return nil
}
