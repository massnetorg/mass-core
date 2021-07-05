package ldb

import (
	"encoding/binary"
	"encoding/hex"

	"github.com/massnetorg/mass-core/database"
	"github.com/massnetorg/mass-core/database/storage"
	"github.com/massnetorg/mass-core/logging"
	"github.com/massnetorg/mass-core/wire"
)

func (db *ChainDb) CountByPrefix(prefix string) (num, size int) {
	mp := make(map[[32]byte]int)

	mpHtsMaxV := 0
	countHts2 := 0
	mpHts := make(map[uint64]int)
	mpHts2 := make(map[uint64]map[[32]byte]int)

	it := db.stor.NewIterator(storage.BytesPrefix([]byte(prefix)))
	defer it.Release()
	for it.Next() {
		num++
		key := it.Key()
		value := it.Value()
		size += len(key) + len(value)
		if prefix == "STL" || prefix == "HTS" {
			var sha [32]byte
			if prefix == "STL" {
				copy(sha[:], key[3:35])
			} else {
				copy(sha[:], key[11:43])

				// count num of scripthash per block
				height := binary.LittleEndian.Uint64(it.Key()[3:11])
				mpHts[height]++
				m, ok := mpHts2[height/40]
				if !ok {
					m = make(map[[32]byte]int)
					mpHts2[height/40] = m
				}
				m[sha]++
				// if mpHts[height] > mpHtsMaxV {
				// 	mpHtsMaxV = mpHts[height]
				// }
				if len(m) > mpHtsMaxV {
					mpHtsMaxV = len(m)
				}
			}
			mp[sha]++
			continue
		}
		if prefix == "BANHGT" {
			count := binary.LittleEndian.Uint16(value[:2])
			if count == 0 {
				if len(value) > 2 {
					panic("----")
				}
				continue
			}
			height := binary.LittleEndian.Uint64(key[6:14])
			for i := 0; i < int(count); i++ {
				pkhash := value[2+32*i : 2+32*i+32]

				// "BANPUB"
				banKey := make([]byte, 38)
				copy(banKey, faultPkShaDataPrefix)
				copy(banKey[6:], pkhash)
				banValue, err := db.stor.Get(banKey)
				if err != nil {
					logging.CPrint(logging.PANIC, "get banned pk error",
						logging.LogFormat{
							"err":    err,
							"height": height,
						})
				}
				if binary.LittleEndian.Uint64(banValue[0:8]) != height {
					panic("height not equal")
				}
				fpk, err := wire.NewFaultPubKeyFromBytes(banValue[41:], wire.DB)
				if err != nil {
					logging.CPrint(logging.PANIC, "NewFaultPubKeyFromBytes error",
						logging.LogFormat{
							"err":    err,
							"height": height,
						})
				}

				logging.CPrint(logging.INFO, "banned pk",
					logging.LogFormat{
						"height":   height,
						"pocpk":    hex.EncodeToString(fpk.PubKey.SerializeCompressed()),
						"header-1": fpk.Testimony[0].Height,
						"header-2": fpk.Testimony[1].Height,
					})
			}
			continue
		}
	}
	if len(mp) > 0 {
		logging.CPrint(logging.INFO, "stats - "+prefix,
			logging.LogFormat{
				"num":                    num,
				"num_scripthash":         len(mp),
				"total_size":             size / 1024 / 1024,
				"avg_num_per_scripthash": num / len(mp),
			})
	}
	if len(mpHts) > 0 {
		for _, m := range mpHts2 {
			countHts2 += len(m)
		}
		logging.CPrint(logging.INFO, "stats >> "+prefix,
			logging.LogFormat{
				"max":                mpHtsMaxV,
				"mpHts2":             len(mpHts2),
				"avg_mpHts2":         countHts2 / len(mpHts2),
				"avg_num_per_height": num / len(mpHts),
			})
	}

	return
}

func (db *ChainDb) ForEach(prefix string, callback func(k, v []byte) error) error {
	it := db.stor.NewIterator(storage.BytesPrefix([]byte(prefix)))
	defer it.Release()
	for it.Next() {
		if err := callback(it.Key(), it.Value()); err != nil {
			return err
		}
	}
	return nil
}

func (db *ChainDb) Get(key []byte) ([]byte, error) {
	return db.stor.Get(key)
}

func (db *ChainDb) CountByPrefixForNew(prefix string) (num, size int) {

	scripthashMap := make(map[[32]byte]int)
	stlMaxV := 0

	it := db.stor.NewIterator(storage.BytesPrefix([]byte(prefix)))
	defer it.Release()
	for it.Next() {
		num++
		key := it.Key()
		value := it.Value()
		size += len(key) + len(value)
		if prefix == "STL" || prefix == "HTS" {
			var sha [32]byte
			if prefix == "STL" {
				copy(sha[:], key[3:35])
				if len(value) > stlMaxV {
					stlMaxV = len(value)
				}
			} else {
				copy(sha[:], key[11:43])
			}
			scripthashMap[sha]++
			continue
		}
		if prefix == "BANHGT" {
			count := binary.LittleEndian.Uint16(value[:2])
			if count == 0 {
				if len(value) > 2 {
					panic("----")
				}
				continue
			}
			height := binary.LittleEndian.Uint64(key[6:14])
			for i := 0; i < int(count); i++ {
				pkhash := value[2+32*i : 2+32*i+32]

				// "BANPUB"
				banKey := make([]byte, 38)
				copy(banKey, faultPkShaDataPrefix)
				copy(banKey[6:], pkhash)
				banValue, err := db.stor.Get(banKey)
				if err != nil {
					logging.CPrint(logging.PANIC, "get banned pk error",
						logging.LogFormat{
							"err":    err,
							"height": height,
						})
				}
				if binary.LittleEndian.Uint64(banValue[0:8]) != height {
					panic("height not equal")
				}
				fpk, err := wire.NewFaultPubKeyFromBytes(banValue[41:], wire.DB)
				if err != nil {
					logging.CPrint(logging.PANIC, "NewFaultPubKeyFromBytes error",
						logging.LogFormat{
							"err":    err,
							"height": height,
						})
				}

				logging.CPrint(logging.INFO, "banned pk",
					logging.LogFormat{
						"height":   height,
						"pocpk":    hex.EncodeToString(fpk.PubKey.SerializeCompressed()),
						"header-1": fpk.Testimony[0].Height,
						"header-2": fpk.Testimony[1].Height,
					})
			}
			continue
		}
	}
	if prefix == "STL" || prefix == "HTS" {
		logging.CPrint(logging.INFO, "stats - "+prefix,
			logging.LogFormat{
				"num":                    num,
				"max_value":              stlMaxV,
				"num_scripthash":         len(scripthashMap),
				"total_size":             size, // / 1024 / 1024,
				"avg_num_per_scripthash": num / len(scripthashMap),
			})
	}
	return
}

func (db *ChainDb) GetAllStaking() (database.StakingNodes, database.StakingNodes, error) {
	staking := make(database.StakingNodes)
	expired := make(database.StakingNodes)

	iterStaking := db.stor.NewIterator(storage.BytesPrefix(recordStakingTx))
	defer iterStaking.Release()
	for iterStaking.Next() {
		expiredHeight, mapKey := mustDecodeStakingTxKey(iterStaking.Key())
		scriptHash, value := mustDecodeStakingTxValue(iterStaking.Value())

		outPoint := wire.OutPoint{
			Hash:  mapKey.txID,
			Index: mapKey.index,
		}
		stakingInfo := database.StakingTxInfo{
			Value:        value,
			BlkHeight:    mapKey.blockHeight,
			FrozenPeriod: expiredHeight - mapKey.blockHeight,
		}
		if !staking.Get(scriptHash).Put(outPoint, stakingInfo) {
			logging.CPrint(logging.ERROR, "duplicated staking item", logging.LogFormat{
				"block_height": stakingInfo.BlkHeight,
				"outpoint":     outPoint,
				"script_hash":  scriptHash,
			})
			return nil, nil, ErrCheckStakingDuplicated
		}
	}

	iterExpired := db.stor.NewIterator(storage.BytesPrefix(recordExpiredStakingTx))
	defer iterExpired.Release()
	for iterExpired.Next() {
		expiredHeight, mapKey := mustDecodeStakingTxKey(iterExpired.Key())
		scriptHash, value := mustDecodeStakingTxValue(iterExpired.Value())

		outPoint := wire.OutPoint{
			Hash:  mapKey.txID,
			Index: mapKey.index,
		}
		stakingInfo := database.StakingTxInfo{
			Value:        value,
			BlkHeight:    mapKey.blockHeight,
			FrozenPeriod: expiredHeight - mapKey.blockHeight,
		}

		if !expired.Get(scriptHash).Put(outPoint, stakingInfo) {
			logging.CPrint(logging.ERROR, "duplicated expired staking item", logging.LogFormat{
				"block_height": stakingInfo.BlkHeight,
				"outpoint":     outPoint,
				"script_hash":  scriptHash,
			})
			return nil, nil, ErrCheckStakingDuplicated
		}
	}

	return staking, expired, nil
}
