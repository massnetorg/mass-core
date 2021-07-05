package ldb

import (
	"encoding/binary"
	"fmt"

	"github.com/massnetorg/mass-core/database/storage"
	"github.com/massnetorg/mass-core/interfaces"
)

var (
	minedBlockIndexPrefix = []byte("MBP")

	PUBLICKEYLENGTH_MASS = 33
	PUBLICKEYLENGTH_CHIA = 48
)

func minedBlockIndexToKey(pubKey interfaces.PublicKey, height uint64) ([]byte, error) {
	pk := pubKey.SerializeCompressed()
	pkLen := len(pk)
	keyLen := 3 + 8 // prefix + height
	switch pkLen {
	case PUBLICKEYLENGTH_MASS, PUBLICKEYLENGTH_CHIA:
		keyLen += pkLen
	default:
		return nil, fmt.Errorf("invalid pk length %d", pkLen)
	}
	key := make([]byte, keyLen)
	copy(key, minedBlockIndexPrefix)
	copy(key[3:3+pkLen], pk)
	binary.LittleEndian.PutUint64(key[3+pkLen:11+pkLen], height)
	return key, nil
}

func minedBlockIndexSearchKey(pubKey interfaces.PublicKey) ([]byte, error) {
	pk := pubKey.SerializeCompressed()
	pkLen := len(pk)
	switch pkLen {
	case PUBLICKEYLENGTH_MASS, PUBLICKEYLENGTH_CHIA:
	default:
		return nil, fmt.Errorf("invalid pk length %d", pkLen)
	}
	key := make([]byte, 3+pkLen)
	copy(key, minedBlockIndexPrefix)
	copy(key[3:3+pkLen], pk)
	return key, nil
}

func updateMinedBlockIndex(batch storage.Batch, connecting bool, pubKey interfaces.PublicKey, height uint64) error {
	key, err := minedBlockIndexToKey(pubKey, height)
	if err != nil {
		return err
	}
	if connecting {
		return batch.Put(key, blankData)
	} else {
		return batch.Delete(key)
	}
}

func (db *ChainDb) FetchMinedBlocks(pubKey interfaces.PublicKey) ([]uint64, error) {
	minedHeights := make([]uint64, 0)
	keyPrefix, err := minedBlockIndexSearchKey(pubKey)
	if err != nil {
		return nil, err
	}
	iter := db.stor.NewIterator(storage.BytesPrefix(keyPrefix))
	defer iter.Release()
	for iter.Next() {
		key := iter.Key()
		height := binary.LittleEndian.Uint64(key[len(key)-8:])
		minedHeights = append(minedHeights, height)
	}
	if err := iter.Error(); err != nil {
		return nil, err
	}
	return minedHeights, nil
}
