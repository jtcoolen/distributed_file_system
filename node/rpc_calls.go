package main

func (t *Node) RetrieveEntry(hash [32]byte, reply *Entry) error {
	*reply = retrieveEntry(hash, t)
	return nil
}
