package trie

import (
	"errors"

	"github.com/massnetorg/mass-core/trie/common"
	"github.com/massnetorg/mass-core/trie/massdb"
	"github.com/massnetorg/mass-core/trie/rawdb"
)

// Database is an intermediate write layer between the trie data structures and
// the disk database. The aim is to accumulate trie writes in-memory and only
// periodically flush a couple tries to disk, garbage collecting the remainder.
//
// Note, the trie Database is **not** thread safe in its mutations, but it **is**
// thread safe in providing individual, independent node access. The rationale
// behind this split design is to provide read access to RPC handlers and sync
// servers even while the trie is executing expensive garbage collection.
type Database struct {
	diskdb massdb.KeyValueStore // Persistent storage for matured trie nodes

	// dirties map[common.Hash]*cachedNode // Data and references relationships of dirty trie nodes
	// oldest  common.Hash                 // Oldest tracked node, flush-list head
	// newest  common.Hash                 // Newest tracked node, flush-list tail

	// gctime  time.Duration      // Time spent on garbage collection since last commit
	// gcnodes uint64             // Nodes garbage collected since last commit
	// gcsize  common.StorageSize // Data storage garbage collected since last commit

	// flushtime  time.Duration      // Time spent on data flushing since last commit
	// flushnodes uint64             // Nodes flushed since last commit
	// flushsize  common.StorageSize // Data storage flushed since last commit

	// dirtiesSize   common.StorageSize // Storage size of the dirty node cache (exc. metadata)
	// childrenSize  common.StorageSize // Storage size of the external children tracking
	// preimagesSize common.StorageSize // Storage size of the preimages cache

	// lock sync.RWMutex
}

// // rawNode is a simple binary blob used to differentiate between collapsed trie
// // nodes and already encoded RLP binary blobs (while at the same time store them
// // in the same cache fields).
// type rawNode []byte

// func (n rawNode) cache() (hashNode, bool) { panic("this should never end up in a live trie") }

// // rawFullNode represents only the useful data content of a full node, with the
// // caches and flags stripped out to minimize its data storage. This type honors
// // the same RLP encoding as the original parent.
// type rawFullNode [17]node

// func (n rawFullNode) cache() (hashNode, bool) { panic("this should never end up in a live trie") }

// // rawShortNode represents only the useful data content of a short node, with the
// // caches and flags stripped out to minimize its data storage. This type honors
// // the same RLP encoding as the original parent.
// type rawShortNode struct {
// 	Key []byte
// 	Val node
// }

// func (n rawShortNode) cache() (hashNode, bool) { panic("this should never end up in a live trie") }

// // cachedNode is all the information we know about a single cached trie node
// // in the memory database write layer.
// type cachedNode struct {
// 	node node   // Cached collapsed trie node, or raw rlp data
// 	size uint16 // Byte size of the useful cached data

// 	parents  uint32                 // Number of live nodes referencing this one
// 	children map[common.Hash]uint16 // External children referenced by this node

// 	flushPrev common.Hash // Previous node in the flush-list
// 	flushNext common.Hash // Next node in the flush-list
// }

// // rlp returns the raw rlp encoded blob of the cached trie node, either directly
// // from the cache, or by regenerating it from the collapsed node.
// func (n *cachedNode) rlp() []byte {
// 	if node, ok := n.node.(rawNode); ok {
// 		return node
// 	}
// 	blob, err := rlp.EncodeToBytes(n.node)
// 	if err != nil {
// 		panic(err)
// 	}
// 	return blob
// }

// // obj returns the decoded and expanded trie node, either directly from the cache,
// // or by regenerating it from the rlp encoded blob.
// func (n *cachedNode) obj(hash common.Hash) node {
// 	if node, ok := n.node.(rawNode); ok {
// 		return mustDecodeNode(hash[:], node)
// 	}
// 	return expandNode(hash[:], n.node)
// }

// // forChilds invokes the callback for all the tracked children of this node,
// // both the implicit ones from inside the node as well as the explicit ones
// // from outside the node.
// func (n *cachedNode) forChilds(onChild func(hash common.Hash)) {
// 	for child := range n.children {
// 		onChild(child)
// 	}
// 	if _, ok := n.node.(rawNode); !ok {
// 		forGatherChildren(n.node, onChild)
// 	}
// }

// // forGatherChildren traverses the node hierarchy of a collapsed storage node and
// // invokes the callback for all the hashnode children.
// func forGatherChildren(n node, onChild func(hash common.Hash)) {
// 	switch n := n.(type) {
// 	case *rawShortNode:
// 		forGatherChildren(n.Val, onChild)
// 	case rawFullNode:
// 		for i := 0; i < 16; i++ {
// 			forGatherChildren(n[i], onChild)
// 		}
// 	case hashNode:
// 		onChild(common.BytesToHash(n))
// 	case valueNode, nil, rawNode:
// 	default:
// 		panic(fmt.Sprintf("unknown node type: %T", n))
// 	}
// }

// // simplifyNode traverses the hierarchy of an expanded memory node and discards
// // all the internal caches, returning a node that only contains the raw data.
// func simplifyNode(n node) node {
// 	switch n := n.(type) {
// 	case *shortNode:
// 		// Short nodes discard the flags and cascade
// 		return &rawShortNode{Key: n.Key, Val: simplifyNode(n.Val)}

// 	case *fullNode:
// 		// Full nodes discard the flags and cascade
// 		node := rawFullNode(n.Children)
// 		for i := 0; i < len(node); i++ {
// 			if node[i] != nil {
// 				node[i] = simplifyNode(node[i])
// 			}
// 		}
// 		return node

// 	case valueNode, hashNode, rawNode:
// 		return n

// 	default:
// 		panic(fmt.Sprintf("unknown node type: %T", n))
// 	}
// }

// // expandNode traverses the node hierarchy of a collapsed storage node and converts
// // all fields and keys into expanded memory form.
// func expandNode(hash hashNode, n node) node {
// 	switch n := n.(type) {
// 	case *rawShortNode:
// 		// Short nodes need key and child expansion
// 		return &shortNode{
// 			Key: compactToHex(n.Key),
// 			Val: expandNode(nil, n.Val),
// 			flags: nodeFlag{
// 				hash: hash,
// 			},
// 		}

// 	case rawFullNode:
// 		// Full nodes need child expansion
// 		node := &fullNode{
// 			flags: nodeFlag{
// 				hash: hash,
// 			},
// 		}
// 		for i := 0; i < len(node.Children); i++ {
// 			if n[i] != nil {
// 				node.Children[i] = expandNode(nil, n[i])
// 			}
// 		}
// 		return node

// 	case valueNode, hashNode:
// 		return n

// 	default:
// 		panic(fmt.Sprintf("unknown node type: %T", n))
// 	}
// }

func NewDatabase(diskdb massdb.KeyValueStore) *Database {
	db := &Database{
		diskdb: diskdb,
		// dirties: map[common.Hash]*cachedNode{{}: {
		// 	children: make(map[common.Hash]uint16),
		// }},
	}
	return db
}

// node retrieves a cached trie node from memory, or returns nil if none can be
// found in the memory cache.
func (db *Database) node(hash common.Hash) node {
	// // Retrieve the node from the dirty cache if available
	// db.lock.RLock()
	// dirty := db.dirties[hash]
	// db.lock.RUnlock()

	// if dirty != nil {
	// 	return dirty.obj(hash)
	// }

	// Content unavailable in memory, attempt to retrieve from disk
	enc, err := db.diskdb.Get(hash[:])
	if err != nil || enc == nil {
		return nil
	}

	n, err := decodeNode(hash[:], enc)
	if err != nil {
		return nil
	}
	switch v := (n).(type) {
	case *fullNode:
		v.flags.hash = hash[:]
	case *shortNode:
		v.flags.hash = hash[:]
	}
	return n
}

// Node retrieves an encoded cached trie node from memory. If it cannot be found
// cached, the method queries the persistent database for the content.
func (db *Database) Node(hash common.Hash) ([]byte, error) {
	// It doesn't make sense to retrieve the metaroot
	if hash == (common.Hash{}) {
		return nil, errors.New("not found")
	}

	// Content unavailable in memory, attempt to retrieve from disk
	enc := rawdb.ReadTrieNode(db.diskdb, hash)
	if len(enc) != 0 {
		return enc, nil
	}
	return nil, errors.New("not found")
}

// // insert inserts a collapsed trie node into the memory database.
// // The blob size must be specified to allow proper size tracking.
// // All nodes inserted by this function will be reference tracked
// // and in theory should only used for **trie nodes** insertion.
// func (db *Database) insert(hash common.Hash, size int, node node) {
// 	// If the node's already cached, skip
// 	if _, ok := db.dirties[hash]; ok {
// 		return
// 	}

// 	// Create the cached entry for this node
// 	entry := &cachedNode{
// 		node:      simplifyNode(node),
// 		size:      uint16(size),
// 		flushPrev: db.newest,
// 	}
// 	entry.forChilds(func(child common.Hash) {
// 		if c := db.dirties[child]; c != nil {
// 			c.parents++
// 		}
// 	})
// 	db.dirties[hash] = entry

// 	// Update the flush-list endpoints
// 	if db.oldest == (common.Hash{}) {
// 		db.oldest, db.newest = hash, hash
// 	} else {
// 		db.dirties[db.newest].flushNext, db.newest = hash, hash
// 	}
// 	db.dirtiesSize += common.StorageSize(common.HashLength + entry.size)
// }
