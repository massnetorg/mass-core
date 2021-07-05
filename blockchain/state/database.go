package state

import (
	"fmt"

	"github.com/massnetorg/mass-core/trie"
	"github.com/massnetorg/mass-core/trie/common"
	"github.com/massnetorg/mass-core/trie/massdb"
)

// Database wraps access to tries and contract code.
type Database interface {
	OpenBindingTrie(root common.Hash) (Trie, error)

	// CopyTrie returns an independent copy of the given trie.
	CopyTrie(Trie) Trie

	// TrieDB retrieves the low level trie database used for data storage.
	TrieDB() *trie.Database
}

// Trie is a Ethereum Merkle Patricia trie.
type Trie interface {
	// // GetKey returns the sha3 preimage of a hashed key that was previously used
	// // to store a value.
	// //
	// // TODO(fjl): remove this when SecureTrie is removed
	// GetKey([]byte) []byte

	// TryGet returns the value for key stored in the trie. The value bytes must
	// not be modified by the caller. If a node was not found in the database, a
	// trie.MissingNodeError is returned.
	TryGet(key []byte) ([]byte, error)

	// TryUpdate associates key with value in the trie. If value has length zero, any
	// existing value is deleted from the trie. The value bytes must not be modified
	// by the caller while they are stored in the trie. If a node was not found in the
	// database, a trie.MissingNodeError is returned.
	TryUpdate(key, value []byte) error

	// TryDelete removes any existing value for key from the trie. If a node was not
	// found in the database, a trie.MissingNodeError is returned.
	TryDelete(key []byte) error

	// Hash returns the root hash of the trie. It does not write to the database and
	// can be used even if the trie doesn't have one.
	Hash() common.Hash

	// Commit writes all nodes to the database.
	Commit() (common.Hash, error)

	// NodeIterator returns an iterator that returns nodes of the trie. Iteration
	// starts at the key after the given start key.
	NodeIterator(startKey []byte) trie.NodeIterator

	// // Prove constructs a Merkle proof for key. The result contains all encoded nodes
	// // on the path to the value at key. The value itself is also included in the last
	// // node and can be retrieved by verifying the proof.
	// //
	// // If the trie does not contain a value for key, the returned proof contains all
	// // nodes of the longest existing prefix of the key (at least the root), ending
	// // with the node that proves the absence of the key.
	// Prove(key []byte, fromLevel uint, proofDb massdb.KeyValueWriter) error
}

// NewDatabase creates a backing store for state. The returned database is safe for
// concurrent use, but does not retain any recent trie nodes in memory. To keep some
// historical state in memory, use the NewDatabaseWithConfig constructor.
func NewDatabase(db massdb.Database) Database {
	return &cachingDB{
		db: trie.NewDatabase(db),
	}
}

type cachingDB struct {
	db *trie.Database
}

// OpenTrie opens the main account trie at a specific root hash.
func (db *cachingDB) OpenBindingTrie(root common.Hash) (Trie, error) {
	tr, err := trie.New(root, db.db)
	if err != nil {
		return nil, err
	}
	return tr, nil
}

// CopyTrie returns an independent copy of the given trie.
func (db *cachingDB) CopyTrie(t Trie) Trie {
	switch t := t.(type) {
	case *trie.Trie:
		return t.Copy()
	default:
		panic(fmt.Errorf("unknown trie type %T", t))
	}
}

// TrieDB retrieves any intermediate trie-node caching layer.
func (db *cachingDB) TrieDB() *trie.Database {
	return db.db
}
