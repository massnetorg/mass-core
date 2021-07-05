package blockchain

import (
	"testing"
	"time"

	"github.com/massnetorg/mass-core/config"
	"github.com/massnetorg/mass-core/massutil"
	"github.com/stretchr/testify/assert"
)

// TestCheckConnectBlock tests the CheckConnectBlock function to ensure it
// fails
func TestCheckConnectBlock(t *testing.T) {
	db, err := newTestChainDb()
	if err != nil {
		panic(err)
	}
	defer db.Close()
	// Create a new database and chain instance to run tests against.
	chain, err := newTestBlockchain(db, "testdata")
	if err != nil {
		t.Errorf("Failed to setup chain instance: %v", err)
		return
	}

	// The genesis block should fail to connect since it's already
	// inserted.
	blk0, err := loadNthBlk(1)
	assert.Nil(t, err)
	genesisHash := blk0.Hash()
	err = chain.checkConnectBlock(NewBlockNode(&blk0.MsgBlock().Header, genesisHash, BFNone), blk0, BFNone)
	assert.Equal(t, ErrConnectGenesis, err)

	blk1, err := loadNthBlk(2)
	assert.Nil(t, err)
	assert.Equal(t, uint64(1), blk1.Height())
	blk1Hash := blk1.Hash()
	err = chain.checkConnectBlock(NewBlockNode(&blk1.MsgBlock().Header, blk1Hash, BFNone), blk1, BFNone)
	assert.Nil(t, err)
}

// TestCheckBlockSanity tests the CheckBlockSanity function to ensure it works
// as expected.
func TestCheckBlockSanity(t *testing.T) {
	pocLimit := config.ChainParams.PocLimit
	block, err := loadNthBlk(22)
	if err != nil {
		t.Fatal(err)
	}

	blk0, err := loadNthBlk(1)
	assert.Nil(t, err)

	err = CheckBlockSanity(block, blk0.MsgBlock().Header.ChainID, pocLimit)
	assert.Nil(t, err)

	// Ensure a block that has a timestamp with a precision higher than one
	// second fails.
	timestamp := block.MsgBlock().Header.Timestamp
	block.MsgBlock().Header.Timestamp = timestamp.Add(time.Nanosecond)
	err = CheckBlockSanity(block, blk0.MsgBlock().Header.ChainID, pocLimit)
	assert.Equal(t, ErrInvalidTime, err)
}

// TestCheckSerializedHeight tests the checkSerializedHeight function with
// various serialized heights and also does negative tests to ensure errors
// and handled properly.
func TestCheckSerializedHeight(t *testing.T) {

	tests := []struct {
		name       string
		blkNth     int    // block index in blks50.dat
		wantHeight uint64 // Expected height
		err        error  // Expected error type
	}{
		{
			"height 1",
			2, 1, nil,
		},
		{
			"height 21",
			22, 21, nil,
		},
		{
			"height 25",
			26, 25, nil,
		},
	}

	t.Logf("Running %d tests", len(tests))
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			block, err := loadNthBlk(test.blkNth)
			if err != nil {
				t.Fatal(err)
			}
			coinbaseTx := block.MsgBlock().Transactions[0]
			tx := massutil.NewTx(coinbaseTx)

			err = TstCheckSerializedHeight(tx, test.wantHeight)
			assert.Equal(t, test.err, err)
		})
	}
}
