package common

import (
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
	}
	return nil
}
