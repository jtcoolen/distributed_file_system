package common

import (
	"net"
	"strings"
)

type RetrieveEntryArgs struct {
	Peer string
	Hash [32]byte
}

type RetrieveEntryByPathArgs struct {
	Peer string
	Path string
}

func (t *Node) RetrieveEntry(args *RetrieveEntryArgs, reply *Entry) error {
	peer, err := GetPeerAddresses(args.Peer)
	dest, err := net.ResolveUDPAddr("udp", string(peer[0]))
	if err != nil {
		return err
	}
	*reply = RetrieveEntry(args.Hash, dest, t)
	if reply.Type == Directory && reply.Name == "" && reply.Children == nil && reply.Data == nil {
		return ErrNotFound
	}
	return nil
}

func (t *Node) RetrieveEntryByPath(args *RetrieveEntryByPathArgs, reply *Entry) error {
	rootHash, err := GetPeerRoot(args.Peer)
	if err != nil {
		return err
	}
	peer, err := GetPeerAddresses(args.Peer)
	dest, err := net.ResolveUDPAddr("udp", string(peer[0]))
	if err != nil {
		return err
	}
	rootEntry := RetrieveEntry(rootHash, dest, t)
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
		return nil
	}
	return ErrNotFound
}

func (t *Node) DisplayDirectoryPath(args *RetrieveEntryByPathArgs, reply *string) error {
	rootHash, err := GetPeerRoot(args.Peer)
	if err != nil {
		return err
	}
	peer, err := GetPeerAddresses(args.Peer)
	dest, err := net.ResolveUDPAddr("udp", string(peer[0]))
	if err != nil {
		return err
	}
	rootEntry := RetrieveEntry(rootHash, dest, t)
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

func (t *Node) ContactNode(peer string, reply *string) error {
	return ContactNodeBehindNat(peer, t)
}
