package ldb

// // Deprecated

// import (
// 	"encoding/binary"
// 	"fmt"

// 	"github.com/massnetorg/mass-core/database"
// 	"github.com/massnetorg/mass-core/database/storage"
// 	"github.com/massnetorg/mass-core/errors"
// 	"github.com/massnetorg/mass-core/interfaces"
// 	"github.com/massnetorg/mass-core/wire"
// )

// var (
// 	pubkblKeyPrefix = "PUBKBL"
// 	// uppkblKey       = []byte("UPPKBL")

// 	// prefix + pk(compressed)
// 	pubkblKeyPrefixLen = len(pubkblKeyPrefix)

// 	// bl + blkHeight
// 	blHeightLen = 1 + 8
// )

// func makePubkblKey(publicKey interfaces.PublicKey) ([]byte, error) {
// 	pkbytes := publicKey.SerializeCompressed()
// 	switch len(pkbytes) {
// 	case PUBLICKEYLENGTH_MASS, PUBLICKEYLENGTH_CHIA:
// 	default:
// 		return nil, fmt.Errorf("invalid pk length %d", len(pkbytes))
// 	}
// 	key := make([]byte, pubkblKeyPrefixLen+len(pkbytes))
// 	copy(key, pubkblKeyPrefix)
// 	copy(key[pubkblKeyPrefixLen:], pkbytes)
// 	return key, nil
// }

// func serializeBLHeights(bitLength uint8, blkHeight uint64) []byte {
// 	buf := make([]byte, blHeightLen)
// 	buf[0] = bitLength
// 	binary.LittleEndian.PutUint64(buf[1:blHeightLen], blkHeight)
// 	return buf
// }

// func deserializeBLHeights(buf []byte) []*database.BLHeight {
// 	count := len(buf) / blHeightLen
// 	blhs := make([]*database.BLHeight, count)
// 	for i := 0; i < count; i++ {
// 		blhs[i] = &database.BLHeight{
// 			BitLength: int(buf[i*blHeightLen]),
// 			BlkHeight: binary.LittleEndian.Uint64(buf[i*blHeightLen+1 : (i+1)*blHeightLen]),
// 		}
// 	}
// 	return blhs
// }

// // func (db *ChainDb) insertPubkblToBatch(batch storage.Batch, publicKey interfaces.PublicKey, bitLengthOrK int, blkHeight uint64) error {
// func (db *ChainDb) insertPubkblToBatch(batch storage.Batch, block *wire.MsgBlock) error {
// 	// db key
// 	key, err := makePubkblKey(block.Header.PublicKey())
// 	if err != nil {
// 		return err
// 	}
// 	// bit_length
// 	bl := block.Header.Proof.BitLength()
// 	// height
// 	blkHeight := block.Header.Height

// 	buf := serializeBLHeights(uint8(bl), blkHeight)
// 	v, err := db.stor.Get(key)
// 	if err != nil {
// 		if err == storage.ErrNotFound {
// 			return batch.Put(key, buf)
// 		}
// 		return err
// 	}
// 	blhs := deserializeBLHeights(v)
// 	lastBl := blhs[len(blhs)-1].BitLength
// 	if bl < lastBl {
// 		return errors.New(fmt.Sprintf("insertPubkblToBatch: unexpected bl %d, last %d, height %d",
// 			bl, lastBl, blkHeight))
// 	}
// 	if bl > lastBl {
// 		v = append(v, buf...)
// 		return batch.Put(key, v)
// 	}
// 	return nil
// }

// func (db *ChainDb) removePubkblWithCheck(batch storage.Batch, block *wire.MsgBlock) error {
// 	key, err := makePubkblKey(block.Header.PublicKey())
// 	if err != nil {
// 		return err
// 	}
// 	buf, err := db.stor.Get(key)
// 	if err != nil {
// 		return err
// 	}
// 	l := len(buf)
// 	bl := buf[l-blHeightLen]
// 	h := binary.LittleEndian.Uint64(buf[l-blHeightLen+1:])
// 	if int(bl) == block.Header.Proof.BitLength() && h == block.Header.Height {
// 		if l == blHeightLen {
// 			return batch.Delete(key)
// 		}
// 		v := buf[:l-blHeightLen]
// 		return batch.Put(key, v)
// 	}
// 	return nil
// }

// func (db *ChainDb) GetPubkeyBlRecord(publicKey interfaces.PublicKey) ([]*database.BLHeight, error) {
// 	key, err := makePubkblKey(publicKey)
// 	if err != nil {
// 		return nil, err
// 	}
// 	v, err := db.stor.Get(key)
// 	if err != nil {
// 		if err == storage.ErrNotFound {
// 			empty := make([]*database.BLHeight, 0)
// 			return empty, nil
// 		}
// 		return nil, err
// 	}
// 	blh := deserializeBLHeights(v)
// 	return blh, nil
// }

//
// func (db *ChainDb) insertPubkbl(publicKey *pocec.PublicKey, bitLength int, blkHeight uint64) error {
// 	key := makePubkblKey(publicKey)
// 	buf := serializeBLHeights(uint8(bitLength), blkHeight)
// 	v, err := db.stor.Get(key)
// 	if err != nil {
// 		if err == storage.ErrNotFound {
// 			return db.stor.Put(key, buf)
// 		}
// 		return err
// 	}
// 	blhs := deserializeBLHeights(v)
// 	lastBl := blhs[len(blhs)-1].BitLength
// 	if bitLength < lastBl {
// 		return errors.New(fmt.Sprintf("insertPubkbl: unexpected bl %d, last %d, height %d",
// 			bitLength, lastBl, blkHeight))
// 	}
// 	if bitLength > lastBl {
// 		v = append(v, buf...)
// 		return db.stor.Put(key, v)
// 	}
// 	return nil
// }

// func (db *ChainDb) fetchPubkblIndexProgress() (uint64, error) {
// 	buf, err := db.stor.Get(uppkblKey)
// 	if err != nil {
// 		if err == storage.ErrNotFound {
// 			return 0, nil
// 		}
// 		return 0, err
// 	}
// 	return binary.LittleEndian.Uint64(buf), nil
// }

// func (db *ChainDb) updatePubkblIndexProgress(height uint64) error {
// 	value := make([]byte, 8)
// 	binary.LittleEndian.PutUint64(value, height)
// 	return db.stor.Put(uppkblKey, value)
// }

// func (db *ChainDb) deletePubkblIndexProgress() error {
// 	return db.stor.Delete(uppkblKey)
// }

// func (db *ChainDb) clearPubkbl() error {
// 	iter := db.stor.NewIterator(storage.BytesPrefix([]byte(pubkblKeyPrefix)))
// 	defer iter.Release()

// 	for iter.Next() {
// 		err := db.stor.Delete(iter.Key())
// 		if err != nil {
// 			return err
// 		}
// 	}
// 	return iter.Error()
// }
