package blockchain

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/massnetorg/mass-core/database"
	"github.com/massnetorg/mass-core/database/ldb"
	"github.com/massnetorg/mass-core/massutil"
	"github.com/massnetorg/mass-core/txscript"
	"github.com/massnetorg/mass-core/wire"
	"github.com/stretchr/testify/assert"
)

type blkhexJson struct {
	BLKHEX string
}

type server struct {
	started bool
}

func (s *server) Stop() error {
	s.started = false
	return nil
}

type logger struct {
	lastLogHeight uint64
}

func (l *logger) LogBlockHeight(blk *massutil.Block) {
	l.lastLogHeight = blk.MsgBlock().Header.Height
	fmt.Printf("log block height: %v, hash: %s\n", blk.MsgBlock().Header.Height, blk.Hash())
}

type chain struct {
	db database.Db
}

func (c *chain) GetBlockByHeight(height uint64) (*massutil.Block, error) {
	sha, err := c.db.FetchBlockShaByHeight(height)
	if err != nil {
		return nil, err
	}
	blk, err := c.db.FetchBlockBySha(sha)
	if err != nil {
		return nil, err
	}
	return blk, nil
}

func (c *chain) NewestSha() (sha *wire.Hash, height uint64, err error) {
	sha, height1, err := c.db.NewestSha()
	if err != nil {
		return nil, 0, err
	}
	height = uint64(height1)
	return sha, height, nil
}

func decodeBlockFromString(blkhex string) (*massutil.Block, error) {
	blkbuf, err := hex.DecodeString(blkhex)
	if err != nil {
		return nil, err
	}
	blk, err := massutil.NewBlockFromBytes(blkbuf, wire.Packet)
	if err != nil {
		return nil, err
	}

	return blk, nil
}

func preCommit(db database.Db, sha *wire.Hash) {
	chainDb := db.(*ldb.ChainDb)
	chainDb.Batch(0).Set(*sha)
	chainDb.Batch(0).Done()
	chainDb.Batch(1).Set(*sha)
	chainDb.Batch(1).Done()
}

// func insertBlock(db database.Db, blkhex string) error {
// 	blk, err := decodeBlockFromString(blkhex)
// 	if err != nil {
// 		return err
// 	}
// 	err = db.SubmitBlock(blk)
// 	if err != nil {
// 		return err
// 	}
// 	commit(db, blk.Hash())
// 	_, height, err := db.NewestSha()
// 	if height != blk.Height() {
// 		return fmt.Errorf("height not equal %d-%d", height, blk.Height())
// 	}
// 	fmt.Printf("insert block %v", height)
// 	//logging.CPrint(logging.INFO, "insert block", logging.LogFormat{"height": height})
// 	return nil
// }

func loadBlockFromJson() (*massutil.Block, error) {
	data, err := ioutil.ReadFile("./testdata/blkwith5000txs.json") //TODO: prepare this block
	if err != nil {
		return nil, err
	}
	var obj blkhexJson
	err = json.Unmarshal(data, &obj)
	if err != nil {
		return nil, err
	}
	blk, err := decodeBlockFromString(obj.BLKHEX)
	if err != nil {
		return nil, err
	}
	return blk, err
}

func TestSubmitBlock(t *testing.T) {
	db, err := newTestChainDb()
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	defer db.Close()

	blks, err := loadTopNBlk(8)
	assert.Nil(t, err)

	for i := 1; i < 8; i++ {
		err = db.SubmitBlock(blks[i])
		assert.Nil(t, err)

		blkHash := blks[i].Hash()
		preCommit(db, blkHash)

		err = db.Commit(*blkHash)
		assert.Nil(t, err)

		_, height, err := db.NewestSha()
		assert.Nil(t, err)
		assert.Equal(t, blks[i].Height(), height)
	}
}

func TestAddrIndexer(t *testing.T) {
	bc, teardown, err := newBlockChain()
	assert.Nil(t, err)
	defer teardown()

	adxr := bc.addrIndexer

	// block height is 3
	blk, err := loadNthBlk(4)
	assert.Nil(t, err)

	// error will be returned for block 1 & block2 not connected
	err = adxr.SyncAttachBlock(nil, blk, nil)
	assert.Equal(t, errUnexpectedHeight, err)

	blks, err := loadTopNBlk(22)
	assert.Nil(t, err)

	presentScriptHash := make(map[string]struct{})
	for i := 1; i < 21; i++ {
		blk := blks[i]
		isOrphan, err := bc.processBlock(blk, BFNone)
		assert.Nil(t, err)
		assert.False(t, isOrphan)

		for _, tx := range blk.Transactions() {
			for _, txout := range tx.MsgTx().TxOut {
				class, ops := txscript.GetScriptInfo(txout.PkScript)
				_, sh, err := txscript.GetParsedOpcode(ops, class)
				assert.Nil(t, err)
				presentScriptHash[wire.Hash(sh).String()] = struct{}{}
			}
		}
	}
	assert.Equal(t, uint64(20), bc.BestBlockHeight())
	t.Log("total present script hash in first 20 blocks:", presentScriptHash)

	// index block 21
	notPresentBefore21 := [][]byte{}
	cache := make(map[string]int)
	for i, tx := range blks[21].Transactions() {
		for j, txout := range tx.MsgTx().TxOut {
			class, ops := txscript.GetScriptInfo(txout.PkScript)
			_, sh, err := txscript.GetParsedOpcode(ops, class)
			assert.Nil(t, err)
			if _, ok := presentScriptHash[wire.Hash(sh).String()]; !ok {
				if _, ok2 := cache[wire.Hash(sh).String()]; !ok2 {
					notPresentBefore21 = append(notPresentBefore21, sh[:])
					cache[wire.Hash(sh).String()] = i*10 + j
				}
			}
		}
	}
	t.Log("total only present in block 21:", cache)
	if len(notPresentBefore21) == 0 {
		t.Fatal("choose another block to continue test")
	}

	// before indexing block 21
	mp, err := bc.db.FetchScriptHashRelatedTx(notPresentBefore21, 0, 21)
	assert.Nil(t, err)
	assert.Zero(t, len(mp))

	node := NewBlockNode(&blks[21].MsgBlock().Header, blks[21].Hash(), BFNone)
	txStore, err := bc.fetchInputTransactions(node, blks[21])
	assert.Nil(t, err)

	err = bc.db.SubmitBlock(blks[21])
	assert.Nil(t, err)
	err = adxr.SyncAttachBlock(nil, blks[21], txStore)
	assert.Nil(t, err)
	blkHash := blks[21].Hash()
	preCommit(bc.db, blkHash)
	err = bc.db.Commit(*blkHash)
	assert.Nil(t, err)

	// after indexing block 21
	mp, err = bc.db.FetchScriptHashRelatedTx(notPresentBefore21, 0, 22)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(mp))
	// assert.Equal(t, 3, len(mp[21]))
}

func TestGetAdxr(t *testing.T) {
	db, err := newTestChainDb()
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	defer db.Close()

	// genesis
	blk, err := loadNthBlk(1)
	assert.Nil(t, err)

	sha, height, err := db.FetchAddrIndexTip()
	assert.Nil(t, err)
	assert.Equal(t, uint64(0), height)
	assert.Equal(t, blk.Hash(), sha)
}

// TODO: + big block test
// // unit testing for [func (a *AddrIndexer) indexBlockAddrs(blk *massutil.Block) (database.BlockAddrIndex, error)]
// // performance test
// func TestIndexBlockAddrs(t *testing.T) {
// 	db, err := newChainDb()
// 	if err != nil {
// 		t.Errorf("%v", err)
// 		return
// 	}
// 	defer db.Close()

// 	s := &server{started: true}
// 	// l := &logger{lastLogHeight: 0}
// 	// c := &chain{db: db}

// 	adxr, err := NewAddrIndexer(db, s)
// 	if err != nil {
// 		t.Errorf("failed to new addrIndexer")
// 		return
// 	}
// 	// adxr.blockLogger = l
// 	// adxr.chain = c

// 	/*
// 		blk is a block with 5000 ordinary transactions(single input and double outputs)
// 		after testing, we found that it takes about 40ms to get addrIndex for this block
// 	*/
// 	blk, err := loadBlockFromJson()
// 	if err != nil {
// 		t.Errorf("%v", err)
// 	}
// 	start := time.Now()
// 	// blockAddrIndex, err := adxr.indexBlockAddrs(blk)
// 	err = adxr.SyncAttachBlock(blk, nil)
// 	if err != nil {
// 		t.Errorf("%v", err)
// 	}
// 	// t.Logf("number: %v", len(blockAddrIndex))
// 	// for _, i := range blockAddrIndex {
// 	// 	t.Logf("each transaction has %v output", len(i))
// 	// }
// 	t.Logf("time cost: %v", time.Since(start))
// }
