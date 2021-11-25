package common

func (t *Node) RetrieveEntry(hash [32]byte, reply *Entry) error {
	*reply = RetrieveEntry(hash, t)
	return nil
}
