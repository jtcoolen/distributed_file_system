package common

import (
	"crypto/sha256"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
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
	if err != nil {
		return err
	}
	if len(peer) == 0 {
		return ErrNoAddresses
	}
	for _, addr := range peer {
		dest, err := net.ResolveUDPAddr("udp", string(addr))
		if err != nil {
			continue
		}
		dests := make([]*net.UDPAddr, 1)
		dests[0] = dest
		if ContactNodeBehindAddr(dests, t) != nil {
			continue
		}
		*reply = RetrieveEntry(args.Hash, args.Peer, dest, t)
		if reply.Type == Directory && reply.Name == "" && reply.Children == nil && reply.Data == nil {
			return ErrNotFound
		}
	}
	return nil
}

func (t *Node) RetrieveEntryByPath(args *RetrieveEntryByPathArgs, reply *Entry) error {
	rootHash, err := GetPeerRoot(args.Peer)
	if err != nil {
		return err
	}
	peer, err := GetPeerAddresses(args.Peer)
	if err != nil {
		return err
	}
	if len(peer) == 0 {
		return ErrNoAddresses
	}

	for _, addr := range peer {
		dest, err := net.ResolveUDPAddr("udp", string(addr))
		if err != nil {
			continue
		}
		dests := make([]*net.UDPAddr, 1)
		dests[0] = dest
		if ContactNodeBehindAddr(dests, t) != nil {
			continue
		}
		rootEntry := RetrieveEntry(rootHash, args.Peer, dest, t)
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
	}
	return ErrNotFound
}

func (t *Node) DisplayDirectoryPath(args *RetrieveEntryByPathArgs, reply *string) error {
	rootHash, err := GetPeerRoot(args.Peer)
	if err != nil {
		return err
	}
	peer, err := GetPeerAddresses(args.Peer)
	if err != nil {
		return err
	}
	if len(peer) == 0 {
		return ErrNoAddresses
	}
	for _, addr := range peer {
		dest, err := net.ResolveUDPAddr("udp", string(addr))
		if err != nil {
			continue
		}
		dests := make([]*net.UDPAddr, 1)
		dests[0] = dest
		if ContactNodeBehindAddr(dests, t) != nil {
			continue
		}
		rootEntry := RetrieveEntry(rootHash, args.Peer, dest, t)
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
	}
	return ErrNotFound
}

func (t *Node) ContactNode(peer string, reply *string) error {
	return ContactNodeBehindNat(peer, t)
}

func (t *Node) GetPeerRootHash(peer string, reply *string) error {
	hash, err := GetPeerRoot(peer)
	if err != nil {
		return err
	}

	*reply = fmt.Sprintf("%x", hash)
	return nil
}

func (t *Node) SendDHKeyRequest(peer string, reply *string) error {
	log.Print("HEY THERE")

	k, err := GenKeyPair()
	if err != nil {
		return err
	}
	t.SessionKeys[peer] = SessionKey{keyPair: k, ready: false}
	id := NewId(t)
	dhRequest, err := makeDHKeyRequest(id, t)
	if err != nil {
		log.Printf("NOOOO")
		log.Print(err)
	}
	addrs, err := GetPeerAddresses(peer)
	if err != nil {
		return err
	}
	for i := range addrs {
		log.Printf("%d", i)
	}
	if len(addrs) == 0 {
		return ErrNoAddresses
	}
	for _, addr := range addrs {
		dest, err := net.ResolveUDPAddr("udp", string(addr))
		if err != nil {
			continue
		}
		dests := make([]*net.UDPAddr, 1)
		dests[0] = dest
		if ContactNodeBehindAddr(dests, t) != nil {
			continue
		}

		waitPacket(id, dhRequest, t, dest, 10*time.Second)

		if k, found := t.SessionKeys[peer]; found {
			log.Print("HERE")
			id = NewId(t)
			dhkey, err := MakeDHKey(id, GetFormattedECDHKey(k.keyPair.PublicKeyX, k.keyPair.PublicKeyY), t)
			if err != nil {
				return nil
			}
			waitPacket(id, dhkey, t, dest, 10*time.Second)
		}

	}

	// Something bad happened
	return nil
}

func (t *Node) UpdateDirectory(path string, reply *string) error {
	f, err := os.OpenFile(path, os.O_RDONLY, 0644) //TODO Minoo is this right?
	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()

	var data []byte
	_, err = f.Read(data)
	if err != nil {
		log.Fatal(err)
	}

	newFile := Entry{
		Type:     Chunk,
		Name:     path,
		Hash:     sha256.Sum256([]byte("")),
		Children: nil,
		Data:     []byte(data),
	}

	newFile.Hash = ComputeHash(&newFile)

	oldDir := t.ExportedDirectory
	newDir := Entry{
		Type:     oldDir.Type,
		Name:     oldDir.Name,
		Hash:     oldDir.Hash,
		Children: append(oldDir.Children, &newFile),
		Data:     oldDir.Data,
	}

	newDir.Hash = ComputeHash(&newDir)

	*t = Node{Name: t.Name,
		PrivateKey:           t.PrivateKey,
		PublicKey:            t.PublicKey,
		FormattedPublicKey:   t.FormattedPublicKey,
		Conn:                 t.Conn,
		BootstrapAddresses:   t.BootstrapAddresses,
		PendingPacketQueries: t.PendingPacketQueries,
		CachedEntries:        t.CachedEntries,
		ExportedDirectory:    &newDir,
		Id:                   t.Id,
		SessionKeys:          t.SessionKeys,
		RegisteredPeers:      t.RegisteredPeers}

	log.Printf("My new root hash is %x", ComputeHash(t.ExportedDirectory))

	return nil
}
