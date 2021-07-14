package cmdutils

import (
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	// _ "github.com/massnetorg/mass-core/database/storage/ldbstorage"

	"github.com/massnetorg/mass-core/blockchain/state"
	"github.com/massnetorg/mass-core/config"
	_ "github.com/massnetorg/mass-core/database/ldb"
	"github.com/massnetorg/mass-core/logging"
	"github.com/massnetorg/mass-core/massutil"
	"github.com/massnetorg/mass-core/wire"

	"github.com/massnetorg/mass-core/blockchain"
	"github.com/massnetorg/mass-core/database"
	"github.com/massnetorg/mass-core/trie/massdb"
	"github.com/massnetorg/mass-core/trie/rawdb"
)

func MakeChain(chainstoreDir string, readonly bool, chainParams *config.Params) (*blockchain.Blockchain, func(), error) {

	chainDb, err := database.OpenDB("leveldb", filepath.Join(chainstoreDir, "blocks.db"), readonly)
	if err != nil {
		if !strings.Contains(err.Error(), "file does not exist") || readonly {
			return nil, nil, err
		}
		chainDb, err = database.CreateDB("leveldb", filepath.Join(chainstoreDir, "blocks.db"))
		if err != nil {
			return nil, nil, err
		}
	}

	path := filepath.Join(chainstoreDir, "bindingstate")

	var bindingDb massdb.Database
	if _, err = os.Stat(path); err != nil {
		if !os.IsNotExist(err) {
			return nil, nil, err
		}
		err = os.MkdirAll(path, 0700)
		if err != nil {
			return nil, nil, err
		}
		bindingDb, err = rawdb.NewLevelDBDatabase(path, 0, 0, "", false)
		bindingDb.Close()
	}

	bindingDb, err = rawdb.NewLevelDBDatabase(path, 0, 0, "", readonly)
	if err != nil {
		chainDb.Close()
		return nil, nil, fmt.Errorf("new leveldb for binding state failed: %v", err)
	}

	close := func() {
		chainDb.Close()
		bindingDb.Close()
	}

	bc, err := blockchain.NewBlockchain(&blockchain.Config{
		DB:             chainDb,
		ChainParams:    chainParams,
		StateBindingDb: state.NewDatabase(bindingDb),
		Checkpoints:    chainParams.Checkpoints,
		CachePath:      filepath.Join(chainstoreDir, blockchain.BlockCacheFileName),
	})
	if err != nil {
		close()
		return nil, nil, err
	}
	return bc, close, nil
}

func encodeBlock(writer io.Writer, block *wire.MsgBlock) error {
	hash := block.BlockHash()
	raw, err := block.Bytes(wire.DB)
	if err != nil {
		return err
	}

	sizeBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(sizeBuf[:], uint32(8+len(hash)+len(raw)))
	heightBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBuf[:], block.Header.Height)

	if _, err := writer.Write(sizeBuf); err != nil {
		return err
	}
	if _, err := writer.Write(heightBuf); err != nil {
		return err
	}
	if _, err := writer.Write(hash[:]); err != nil {
		return err
	}
	_, err = writer.Write(raw)
	return err
}

func decodeBlock(reader io.Reader) (*wire.MsgBlock, error) {
	// read size
	sizeBuf := make([]byte, 4)
	n, err := io.ReadFull(reader, sizeBuf)
	if err != nil {
		return nil, err
	}
	if n != 4 {
		return nil, fmt.Errorf("read error bytes %d, expect 4", n)
	}
	size := binary.BigEndian.Uint32(sizeBuf)

	// read height, hash, raw
	data := make([]byte, size)
	n, err = io.ReadFull(reader, data)
	if err != nil {
		return nil, err
	}
	if n != int(size) {
		return nil, fmt.Errorf("read error bytes %d, expect %d", n, size)
	}
	height := binary.BigEndian.Uint64(data[0:8])
	var hash wire.Hash
	copy(hash[:], data[8:8+len(hash)])
	block := wire.NewEmptyMsgBlock()
	err = block.SetBytes(data[8+len(hash):], wire.DB)
	if err != nil {
		return nil, err
	}

	if height != block.Header.Height {
		return nil, fmt.Errorf("height mismatched %d, %d", height, block.Header.Height)
	}
	if hash != block.BlockHash() {
		return nil, fmt.Errorf("height mismatched %s, %s", hash, block.BlockHash())
	}
	return block, nil
}

// ExportChain exports a blockchain into the specified file, truncating any data
// already present in the file.
func ExportChain(bc *blockchain.Blockchain, fn string, last uint64) error {
	logging.CPrint(logging.INFO, "Exporting blockchain", logging.LogFormat{"file": fn})

	// Open the file handle and potentially wrap with a gzip stream
	fh, err := os.OpenFile(fn, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return err
	}
	defer fh.Close()

	var writer io.Writer = fh
	if strings.HasSuffix(fn, ".gz") {
		writer = gzip.NewWriter(writer)
		defer writer.(*gzip.Writer).Close()
	}
	// Iterate over the blocks and export them
	if last == 0 || last > bc.BestBlockHeight() {
		last = bc.BestBlockHeight()
	}
	var lastHash wire.Hash
	for height := uint64(0); height <= last; height++ {
		block, err := bc.GetBlockByHeight(height)
		if err != nil {
			return err
		}
		if err = encodeBlock(writer, block.MsgBlock()); err != nil {
			return err
		}
		if height != 0 && height%2000 == 0 {
			fmt.Printf("Exported %d\n", height)
		}
		if height == last {
			lastHash = block.MsgBlock().BlockHash()
		}
	}

	logging.CPrint(logging.INFO, "Exported blockchain", logging.LogFormat{"file": fn, "last": last, "hash": lastHash})

	return nil
}

func ImportChain(bc *blockchain.Blockchain, fn string, noExpensiveValidation bool) error {
	logging.CPrint(logging.INFO, "Importing blockchain", logging.LogFormat{"file": fn})

	// Watch for Ctrl-C while the import is running.
	// If a signal is received, the import will stop at the next batch.
	interrupt := make(chan os.Signal, 1)
	stop := make(chan struct{})
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(interrupt)
	defer close(interrupt)
	go func() {
		if _, ok := <-interrupt; ok {
			logging.CPrint(logging.INFO, "Interrupted during import, stopping at next batch")
		}
		close(stop)
	}()
	checkInterrupt := func() bool {
		select {
		case <-stop:
			return true
		default:
			return false
		}
	}

	// reader
	fh, err := os.Open(fn)
	if err != nil {
		return err
	}
	defer fh.Close()

	var reader io.Reader = fh
	if strings.HasSuffix(fn, ".gz") {
		if reader, err = gzip.NewReader(reader); err != nil {
			return err
		}
	}

	// reader = bufio.NewReaderSize(reader, 2<<20)

	// Run actual the import.
	importBatchSize := 2000
	blocks := make([]*wire.MsgBlock, importBatchSize)
	n := 0
	for batch := 0; ; batch++ {
		// Load a batch of RLP blocks.
		if checkInterrupt() {
			return fmt.Errorf("interrupted")
		}
		i := 0
		for ; i < importBatchSize; i++ {
			block, err := decodeBlock(reader)
			if err != nil {
				if err == io.EOF {
					break
				}
				return fmt.Errorf("at block %d: %v", n, err)
			}
			// don't import first block
			if block.Header.Height == 0 {
				i--
				continue
			}
			blocks[i] = block
			n++
		}
		if i == 0 {
			break
		}
		// Import the batch.
		if checkInterrupt() {
			return fmt.Errorf("interrupted")
		}
		missing := missingBlocks(bc, blocks[:i])
		if len(missing) == 0 {
			logging.CPrint(logging.INFO, "Skipping batch as all blocks present", logging.LogFormat{
				"batch": batch,
				"first": blocks[0].BlockHash(),
				"last":  blocks[i-1].BlockHash(),
			})
			continue
		}

		for _, b := range missing {
			mb := massutil.NewBlock(b)
			mb.ImportOptions = &massutil.ImportOptions{}
			if noExpensiveValidation {
				mb.ImportOptions.NotRunScripts = true
			}
			isOrphan, err := bc.InsertChain(mb)
			if err != nil {
				return fmt.Errorf("invalid block %d: %v", n, err)
			}
			if isOrphan {
				return fmt.Errorf("orphan block %d: %d", n, b.Header.Height)
			}
		}
		fmt.Printf("batch %d, head %d, hash %s\n", batch, bc.BestBlockHeight(), bc.BestBlockHash())
	}

	logging.CPrint(logging.INFO, "Imported blockchain", logging.LogFormat{
		"height": bc.BestBlockHeight(),
		"last":   bc.BestBlockHash(),
	})
	return nil
}

func missingBlocks(bc *blockchain.Blockchain, blocks []*wire.MsgBlock) []*wire.MsgBlock {
	head := bc.BestBlockNode()
	for i, block := range blocks {
		if head.Height > block.Header.Height {
			continue
		}

		if head.Height == block.Header.Height {
			if *head.Hash != block.BlockHash() {
				logging.CPrint(logging.PANIC, "unexpected block at head", logging.LogFormat{
					"height":   head.Height,
					"head":     head.Hash,
					"imported": block.BlockHash(),
				})
			}
			continue
		}

		if block.Header.Height != head.Height+1 {
			logging.CPrint(logging.PANIC, "unexpected next block height of head", logging.LogFormat{
				"head":     head.Height,
				"imported": block.Header.Height,
			})
		}

		if block.Header.Previous != *head.Hash {
			logging.CPrint(logging.PANIC, "unexpected next block hash of head", logging.LogFormat{
				"head":     head.Hash,
				"imported": block.BlockHash(),
			})
		}
		return blocks[i:]
	}
	return nil
}
