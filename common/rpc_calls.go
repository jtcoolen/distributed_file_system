package common

import (
	"crypto/sha256"
	"fmt"
	"log"
	"net"
	"os"
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
		reply, err = RetrieveEntry(args.Hash, args.Peer, dest, t)
		if err != nil {
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
		rootEntry, err := RetrieveEntry(rootHash, args.Peer, dest, t)
		if err != nil {
			return err
		}
		s := strings.Split(args.Path, "/")
		if s[0] == "" {
			s = s[1:]
		}
		if s[len(s)-1] == "" {
			s = s[:len(s)-1]
		}
		entry := FindEntryByPath(s, rootEntry)
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
		rootEntry, err := RetrieveEntry(rootHash, args.Peer, dest, t)
		if err != nil {
			return err
		}
		s := strings.Split(args.Path, "/")
		if s[0] == "" {
			s = s[1:]
		}
		if s[len(s)-1] == "" {
			s = s[:len(s)-1]
		}
		str, err := DisplayDirectoryFromPath(s, rootEntry)
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

		waitPacket(id, dhRequest, t, dest)

		if k, found := t.SessionKeys[peer]; found {
			log.Print("HERE")
			id = NewId(t)
			dhkey, err := MakeDHKey(id, GetFormattedECDHKey(k.keyPair.PublicKeyX, k.keyPair.PublicKeyY), t)
			if err != nil {
				return nil
			}
			waitPacket(id, dhkey, t, dest)
			return nil
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

	data := make([]byte, 1024)
	_, err = f.Read(data)
	if err != nil {
		return err
	}

	newFile := &Entry{
		Type:     Chunk,
		Name:     path,
		Hash:     sha256.Sum256([]byte("")),
		Children: nil,
		Data:     []byte(data),
	}

	newFile.Hash = ComputeHash(newFile)

	t.ExportedDirectory.Children = append(t.ExportedDirectory.Children, newFile)
	t.ExportedDirectory.Hash = ComputeHash(t.ExportedDirectory)

	packet, err := makeRoot(NewId(t), t.ExportedDirectory.Hash, t)

	if err == nil {
		for _, addr := range t.BootstrapAddresses {
			log.Printf("addr : %s \n", addr)
			t.Conn.WriteToUDP(packet, addr)
		}
	} else {
		log.Printf("%s", err)
	}

	log.Printf("My new root hash is %x", ComputeHash(t.ExportedDirectory))

	return nil
}
