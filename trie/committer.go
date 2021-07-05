package trie

import (
	"errors"
	"fmt"

	"github.com/massnetorg/mass-core/logging"
	"github.com/massnetorg/mass-core/trie/common"
	"github.com/massnetorg/mass-core/trie/massdb"
	"github.com/massnetorg/mass-core/trie/rawdb"
)

// committer is a type used for the trie Commit operation. A committer has some
// internal preallocated temp space, and also a callback that is invoked when
// leaves are committed. The leafs are passed through the `leafCh`,  to allow
// some level of parallelism.
// By 'some level' of parallelism, it's still the case that all leaves will be
// processed sequentially - onleaf will never be called in parallel or out of order.
type committer struct {
	// sha crypto.KeccakState

}

// // committers live in a global sync.Pool
// var committerPool = sync.Pool{
// 	New: func() interface{} {
// 		return &committer{
// 			// tmp: make(sliceBuffer, 0, 550), // cap is as large as a full fullNode.
// 			// sha: sha3.NewLegacyKeccak256().(crypto.KeccakState),
// 		}
// 	},
// }

// newCommitter creates a new committer or picks one from the pool.
func newCommitter() *committer {
	// return committerPool.Get().(*committer)
	return &committer{}
}

// func returnCommitterToPool(h *committer) {
// 	committerPool.Put(h)
// }

// commit collapses a node down into a hash node and inserts it into the database
func (c *committer) Commit(n node, db *Database) (hashNode, error) {

	if db == nil {
		return nil, errors.New("no db provided")
	}

	batch := db.diskdb.NewBatch()

	h, err := c.commit(n, batch)
	if err != nil {
		return nil, err
	}

	if err := batch.Write(); err != nil {
		return nil, err
	}

	return h.(hashNode), nil
}

// commit collapses a node down into a hash node and inserts it into the database
func (c *committer) commit(n node, batch massdb.Batch) (node, error) {
	// if this path is clean, use available cached data
	hash, dirty := n.cache()
	if hash != nil && !dirty {
		return hash, nil
	}
	// Commit children, then parent, and remove remove the dirty flag.
	switch cn := n.(type) {
	case *shortNode:
		// Commit child
		collapsed := cn.copy()

		// If the child is fullnode, recursively commit.
		// Otherwise it can only be hashNode or valueNode.
		if _, ok := cn.Val.(*fullNode); ok {
			childV, err := c.commit(cn.Val, batch)
			if err != nil {
				return nil, err
			}
			collapsed.Val = childV
		}
		// The key needs to be copied, since we're delivering it to database
		collapsed.Key = hexToCompact(cn.Key)
		hashedNode := c.store(collapsed, batch)
		if hn, ok := hashedNode.(hashNode); ok {
			return hn, nil
		}
		return collapsed, nil
	case *fullNode:
		hashedKids, err := c.commitChildren(cn, batch)
		if err != nil {
			return nil, err
		}
		collapsed := cn.copy()
		collapsed.Children = hashedKids

		hashedNode := c.store(collapsed, batch)
		if hn, ok := hashedNode.(hashNode); ok {
			return hn, nil
		}
		return collapsed, nil
	case hashNode:
		return cn, nil
	default:
		// nil, valuenode shouldn't be committed
		panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

// commitChildren commits the children of the given fullnode
func (c *committer) commitChildren(n *fullNode, batch massdb.Batch) ([17]node, error) {
	var children [17]node
	for i := 0; i < 16; i++ {
		child := n.Children[i]
		if child == nil {
			continue
		}
		// If it's the hashed child, save the hash value directly.
		// Note: it's impossible that the child in range [0, 15]
		// is a valuenode.
		if hn, ok := child.(hashNode); ok {
			children[i] = hn
			continue
		}
		// Commit the child recursively and store the "hashed" value.
		// Note the returned node can be some embedded nodes, so it's
		// possible the type is not hashnode.
		hashed, err := c.commit(child, batch)
		if err != nil {
			return children, err
		}
		children[i] = hashed
	}
	// For the 17th child, it's possible the type is valuenode.
	if n.Children[16] != nil {
		children[16] = n.Children[16]
	}
	return children, nil
}

// // store hashes the node n and if we have a storage layer specified, it writes
// // the key/value pair to it and tracks any node->child references as well as any
// // node->external trie references.
// func (c *committer) store(n node, db *Database) node {
// 	// Larger nodes are replaced by their hash and stored in the database.
// 	var (
// 		hash, _ = n.cache()
// 		size    int
// 	)
// 	if hash == nil {
// 		// This was not generated - must be a small node stored in the parent.
// 		// In theory we should apply the leafCall here if it's not nil(embedded
// 		// node usually contains value). But small value(less than 32bytes) is
// 		// not our target.
// 		return n
// 	} else {
// 		// We have the hash already, estimate the RLP encoding-size of the node.
// 		// The size is used for mem tracking, does not need to be exact
// 		size = estimateSize(n)
// 	}

// 	if db != nil {
// 		// No leaf-callback used, but there's still a database. Do serial
// 		// insertion
// 		db.lock.Lock()
// 		db.insert(common.BytesToHash(hash), size, n)
// 		db.lock.Unlock()
// 	}
// 	return hash
// }

// // estimateSize estimates the size of an rlp-encoded node, without actually
// // rlp-encoding it (zero allocs). This method has been experimentally tried, and with a trie
// // with 1000 leafs, the only errors above 1% are on small shortnodes, where this
// // method overestimates by 2 or 3 bytes (e.g. 37 instead of 35)
// func estimateSize(n node) int {
// 	switch n := n.(type) {
// 	case *shortNode:
// 		// A short node contains a compacted key, and a value.
// 		return 3 + len(n.Key) + estimateSize(n.Val)
// 	case *fullNode:
// 		// A full node contains up to 16 hashes (some nils), and a key
// 		s := 3
// 		for i := 0; i < 16; i++ {
// 			if child := n.Children[i]; child != nil {
// 				s += estimateSize(child)
// 			} else {
// 				s++
// 			}
// 		}
// 		return s
// 	case valueNode:
// 		return 1 + len(n)
// 	case hashNode:
// 		return 1 + len(n)
// 	default:
// 		panic(fmt.Sprintf("node type %T", n))
// 	}
// }

//===============
func (c *committer) store(n node, batch massdb.Batch) node {
	hash, _ := n.cache()

	if hash == nil {
		// This was not generated - must be a small node stored in the parent.
		// In theory we should apply the leafCall here if it's not nil(embedded
		// node usually contains value). But small value(less than 32bytes) is
		// not our target.
		return n
	}

	enc, err := encodeNode(n)
	if err != nil {
		logging.CPrint(logging.PANIC, "failed to encode node", logging.LogFormat{"err": err})
	}

	rawdb.WriteTrieNode(batch, common.BytesToHash(hash), enc)
	return hash
}
