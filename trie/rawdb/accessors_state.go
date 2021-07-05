package rawdb

import (
	"github.com/massnetorg/mass-core/logging"
	"github.com/massnetorg/mass-core/trie/common"
	"github.com/massnetorg/mass-core/trie/massdb"
)

// ReadTrieNode retrieves the trie node of the provided hash.
func ReadTrieNode(db massdb.KeyValueReader, hash common.Hash) []byte {
	data, _ := db.Get(hash.Bytes())
	return data
}

// WriteTrieNode writes the provided trie node database.
func WriteTrieNode(db massdb.KeyValueWriter, hash common.Hash, node []byte) {
	if err := db.Put(hash.Bytes(), node); err != nil {
		logging.CPrint(logging.PANIC, "failed to store trie node", logging.LogFormat{"err": err})
	}
}
