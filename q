[1mdiff --git a/dfs_node.go b/dfs_node.go[m
[1mindex 7262336..c040d9f 100644[m
[1m--- a/dfs_node.go[m
[1m+++ b/dfs_node.go[m
[36m@@ -181,7 +181,7 @@[m [mfunc downloadJuliuszTree(node *Node) Entry {[m
 		switch kind {[m
 		case 0: // Chunk[m
 			currentEntry.entryType = Chunk[m
[31m-			len := int(packetLength) - 1 - hashLength[m
[32m+[m			[32mlen := int(packetLength) - 1[m
 			copy(h[:], packet[headerLength:headerLength+hashLength])[m
 			currentEntry.data = make([]byte, len)[m
 			copy(currentEntry.data, packet[headerLength+hashLength+1:headerLength+int(packetLength)])[m
