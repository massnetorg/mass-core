package blockchain

import (
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/golang/groupcache/lru"
	"github.com/massnetorg/mass-core/blockchain/state"
	"github.com/massnetorg/mass-core/config"
	chaincfg "github.com/massnetorg/mass-core/config"
	"github.com/massnetorg/mass-core/consensus/forks"
	"github.com/massnetorg/mass-core/database"
	"github.com/massnetorg/mass-core/database/storage"
	"github.com/massnetorg/mass-core/interfaces"
	"github.com/massnetorg/mass-core/logging"
	"github.com/massnetorg/mass-core/massutil"
	"github.com/massnetorg/mass-core/trie/common"
	"github.com/massnetorg/mass-core/txscript"
	"github.com/massnetorg/mass-core/wire"
)

const (
	maxProcessBlockChSize = 1024
	sigCacheMaxSize       = 50000
	hashCacheMaxSize      = sigCacheMaxSize
	blockErrCacheSize     = 500
)

type chainInfo struct {
	genesisBlock *massutil.Block
	genesisHash  wire.Hash
	genesisTime  time.Time
	chainID      wire.Hash
}

type processBlockResponse struct {
	isOrphan bool
	err      error
}

type processBlockMsg struct {
	block *massutil.Block
	flags BehaviorFlags
	reply chan processBlockResponse
}

type Listener interface {
	OnBlockConnected(*wire.MsgBlock) error
	OnTransactionReceived(tx *wire.MsgTx) error
}

type Config struct {
	DB             database.Db
	StateBindingDb state.Database
	ChainParams    *chaincfg.Params
	Checkpoints    []chaincfg.Checkpoint
	CachePath      string
}

type Blockchain struct {
	// The following fields are set when the instance is created and can't
	// be changed afterwards, so there is no need to protect them with a
	// separate mutex.
	checkpoints         []chaincfg.Checkpoint
	checkpointsByHeight map[uint64]*chaincfg.Checkpoint
	chainParams         *chaincfg.Params
	db                  database.Db
	stateBindingDb      state.Database
	info                *chainInfo

	l              sync.RWMutex
	cond           sync.Cond
	blockCache     *blockCache           // cache storing side chain blocks
	blockTree      *BlockTree            // tree index consists of blocks
	txPool         *TxPool               // pool of transactions
	proposalPool   *ProposalPool         // pool of proposals
	addrIndexer    *AddrIndexer          // address indexer
	dmd            *DoubleMiningDetector // double mining detector
	processBlockCh chan *processBlockMsg
	listeners      map[Listener]struct{}

	errCache  *lru.Cache
	sigCache  *txscript.SigCache
	hashCache *txscript.HashCache

	// These fields are related to checkpoint handling.  They are protected
	// by the chain lock.
	nextCheckpoint *config.Checkpoint
	checkpointNode *BlockNode
}

func NewBlockchain(config *Config) (*Blockchain, error) {

	// Generate a checkpoint by height map from the provided checkpoints
	// and assert the provided checkpoints are sorted by height as required.
	var checkpointsByHeight map[uint64]*chaincfg.Checkpoint
	var prevCheckpointHeight uint64
	if len(config.Checkpoints) > 0 {
		checkpointsByHeight = make(map[uint64]*chaincfg.Checkpoint)
		for i := range config.Checkpoints {
			checkpoint := &config.Checkpoints[i]
			if checkpoint.Height <= prevCheckpointHeight {
				return nil, fmt.Errorf("NewBlockchain checkpoints are not sorted by height")
			}

			checkpointsByHeight[checkpoint.Height] = checkpoint
			prevCheckpointHeight = checkpoint.Height
		}
	}

	chain := &Blockchain{
		checkpoints:         config.Checkpoints,
		checkpointsByHeight: checkpointsByHeight,
		db:                  config.DB,
		chainParams:         config.ChainParams,
		stateBindingDb:      config.StateBindingDb,

		blockTree:      NewBlockTree(),
		dmd:            NewDoubleMiningDetector(config.DB),
		processBlockCh: make(chan *processBlockMsg, maxProcessBlockChSize),
		errCache:       lru.New(blockErrCacheSize),
		hashCache:      txscript.NewHashCache(hashCacheMaxSize),
		listeners:      make(map[Listener]struct{}),
	}
	chain.cond.L = &sync.Mutex{}

	var err error
	if chain.blockCache, err = initBlockCache(config.CachePath); err != nil {
		return nil, err
	}

	chain.txPool = NewTxPool(chain, chain.sigCache, chain.hashCache)

	if punishments, err := chain.RetrievePunishment(); err == nil {
		chain.proposalPool = NewProposalPool(punishments)
	} else {
		return nil, err
	}

	if chain.addrIndexer, err = NewAddrIndexer(chain.db, chain.stateBindingDb); err != nil {
		return nil, err
	}

	var genesisBlock *massutil.Block
	genesisHash, err := chain.db.FetchBlockShaByHeight(0)
	if err != nil {
		if err != storage.ErrNotFound {
			return nil, err
		}
		genesisBlock = massutil.NewBlock(config.ChainParams.GenesisBlock)
		if err := chain.db.InitByGenesisBlock(genesisBlock); err != nil {
			return nil, err
		}
		genesisHash = genesisBlock.Hash()
	} else {
		if genesisBlock, err = chain.db.FetchBlockBySha(genesisHash); err != nil {
			return nil, err
		}
	}
	if *genesisHash != *config.ChainParams.GenesisHash {
		return nil, fmt.Errorf("error genesis hash")
	}
	chain.info = &chainInfo{
		genesisBlock: genesisBlock,
		genesisHash:  *genesisHash,
		genesisTime:  genesisBlock.MsgBlock().Header.Timestamp,
		chainID:      genesisBlock.MsgBlock().Header.ChainID,
	}

	if err := chain.generateInitialIndex(); err != nil {
		return nil, err
	}

	go chain.blockProcessor()

	return chain, nil
}

func (chain *Blockchain) generateInitialIndex() error {
	// Return an error if the has already been modified.
	if chain.blockTree.rootBlockNode() != nil {
		return errIndexAlreadyInitialized
	}

	// Grab the latest block height for the main chain from the database.
	_, endHeight, err := chain.db.NewestSha()
	if err != nil {
		return err
	}

	// Calculate the starting height based on the minimum number of nodes
	// needed in memory.
	var startHeight uint64
	if endHeight >= minMemoryNodes {
		startHeight = endHeight - minMemoryNodes
	}

	// Loop forwards through each block loading the node into the index for
	// the block.
	// FetchBlockBySha multiple times with the appropriate indices as needed.
	for start := startHeight; start <= endHeight; {
		hashList, err := chain.db.FetchHeightRange(start, endHeight+1)
		if err != nil {
			return err
		}

		// The database did not return any further hashes.  Break out of
		// the loop now.
		if len(hashList) == 0 {
			break
		}

		// Loop forwards through each block loading the node into the
		// index for the block.
		for _, hash := range hashList {
			// Make a copy of the hash to make sure there are no
			// references into the list so it can be freed.
			hashCopy := hash
			node, err := chain.loadBlockNode(&hashCopy)
			if err != nil {
				return err
			}

			// This node is now the end of the best chain.
			chain.blockTree.setBestBlockNode(node)
		}

		// Start at the next block after the latest one on the next loop
		// iteration.
		start += uint64(len(hashList))
	}

	return nil
}

func (chain *Blockchain) blockExists(hash *wire.Hash) bool {
	// Check memory chain first (could be main chain or side chain blocks).
	if chain.blockTree.nodeExists(hash) {
		return true
	}
	// Check in database (rest of main chain not in memory).
	exists, err := chain.db.ExistsSha(hash)
	if err != nil {
		logging.CPrint(logging.ERROR, "fail to check block existence from db",
			logging.LogFormat{"hash": hash, "err": err})
	}
	return exists
}

func (chain *Blockchain) loadBlockNode(hash *wire.Hash) (*BlockNode, error) {
	blockHeader, err := chain.db.FetchBlockHeaderBySha(hash)
	if err != nil {
		return nil, err
	}

	node := NewBlockNode(blockHeader, hash, BFNone)
	node.InMainChain = true

	// deal with leaf node
	if chain.blockTree.nodeExists(&node.Previous) {
		if err := chain.blockTree.attachBlockNode(node); err != nil {
			return nil, err
		}
		return node, nil
	}

	// deal with expand root
	if root := chain.blockTree.rootBlockNode(); root != nil && node.Hash.IsEqual(&root.Previous) {
		if err := chain.blockTree.expandRootBlockNode(node); err != nil {
			return nil, err
		}
		return node, nil
	}

	// deal with set root
	if root := chain.blockTree.rootBlockNode(); root == nil {
		if err := chain.blockTree.setRootBlockNode(node); err != nil {
			return nil, err
		}
		return node, nil
	}

	// deal with orphan node
	return nil, errExpandOrphanRootBlockNode
}

func (chain *Blockchain) getPrevNodeFromBlock(block *massutil.Block) (*BlockNode, error) {
	// Genesis block.
	prevHash := &block.MsgBlock().Header.Previous
	if prevHash.IsEqual(zeroHash) {
		return nil, nil
	}

	// Return the existing previous block node if it's already there.
	if bn, ok := chain.blockTree.getBlockNode(prevHash); ok {
		return bn, nil
	}

	// Dynamically load the previous block from the block database, create
	// a new block node for it, and update the memory chain accordingly.
	prevBlockNode, err := chain.loadBlockNode(prevHash)
	if err != nil {
		return nil, err
	}
	return prevBlockNode, nil
}

func (chain *Blockchain) getPrevNodeFromNode(node *BlockNode) (*BlockNode, error) {
	// Return the existing previous block node if it's already there.
	if node.Parent != nil {
		return node.Parent, nil
	}

	// Return node in blockTree index
	if parent, exists := chain.blockTree.getBlockNode(&node.Previous); exists {
		return parent, nil
	}

	// Genesis block.
	if node.Hash.IsEqual(chain.chainParams.GenesisHash) {
		return nil, nil
	}

	// Dynamically load the previous block from the block database, create
	// a new block node for it, and update the memory chain accordingly.
	prevBlockNode, err := chain.loadBlockNode(&node.Previous)
	if err != nil {
		return nil, err
	}

	return prevBlockNode, nil
}

func (chain *Blockchain) blockProcessor() {
	for msg := range chain.processBlockCh {
		isOrphan, err := chain.processBlock(msg.block, msg.flags)
		msg.reply <- processBlockResponse{isOrphan: isOrphan, err: err}
	}
}

// processBlock is the entry for handle block insert
func (chain *Blockchain) execProcessBlock(block *massutil.Block, flags BehaviorFlags) (bool, error) {
	reply := make(chan processBlockResponse, 1)
	chain.processBlockCh <- &processBlockMsg{block: block, flags: flags, reply: reply}
	response := <-reply
	return response.isOrphan, response.err
}

func (chain *Blockchain) BestBlockNode() *BlockNode {
	return chain.blockTree.bestBlockNode()
}

func (chain *Blockchain) BestBlockHeader() *wire.BlockHeader {
	return chain.blockTree.bestBlockNode().BlockHeader()
}

func (chain *Blockchain) BestBlockHeight() uint64 {
	return chain.blockTree.bestBlockNode().Height
}

func (chain *Blockchain) BestBlockHash() *wire.Hash {
	return chain.blockTree.bestBlockNode().Hash
}

func (chain *Blockchain) GetBlockByHash(hash *wire.Hash) (*massutil.Block, error) {
	return chain.db.FetchBlockBySha(hash)
}

func (chain *Blockchain) GetBlockByHeight(height uint64) (*massutil.Block, error) {
	hash, err := chain.db.FetchBlockShaByHeight(height)
	if err != nil {
		return nil, err
	}
	return chain.db.FetchBlockBySha(hash)
}

func (chain *Blockchain) GetHeaderByHash(hash *wire.Hash) (*wire.BlockHeader, error) {
	if node, exists := chain.blockTree.getBlockNode(hash); exists {
		return node.BlockHeader(), nil
	}
	return chain.db.FetchBlockHeaderBySha(hash)
}

func (chain *Blockchain) GetHeaderByHeight(height uint64) (*wire.BlockHeader, error) {
	hash, err := chain.db.FetchBlockShaByHeight(height)
	if err != nil {
		return nil, err
	}
	return chain.db.FetchBlockHeaderBySha(hash)
}

func (chain *Blockchain) GetBlockHashByHeight(height uint64) (*wire.Hash, error) {
	return chain.db.FetchBlockShaByHeight(height)
}

func (chain *Blockchain) GetTransactionInDB(hash *wire.Hash) ([]*database.TxReply, error) {
	return chain.db.FetchTxBySha(hash)
}

func (chain *Blockchain) InMainChain(hash wire.Hash) bool {
	if node, exists := chain.blockTree.getBlockNode(&hash); exists {
		return node.InMainChain
	}
	height, err := chain.db.FetchBlockHeightBySha(&hash)
	if err != nil {
		return false
	}
	dbHash, err := chain.db.FetchBlockShaByHeight(height)
	if err != nil {
		return false
	}
	return *dbHash == hash
}

func (chain *Blockchain) FetchMinedBlocks(pubKey interfaces.PublicKey) ([]uint64, error) {
	return chain.db.FetchMinedBlocks(pubKey)
}

func (chain *Blockchain) GetTransaction(hash *wire.Hash) (*wire.MsgTx, error) {
	txList, err := chain.db.FetchTxBySha(hash)
	if err != nil {
		return nil, err
	}
	if len(txList) == 0 {
		return nil, database.ErrTxShaMissing
	}
	return txList[0].Tx, nil
}

// ProcessBlock is the entry for chain update
func (chain *Blockchain) ProcessBlock(block *massutil.Block) (bool, error) {
	return chain.execProcessBlock(block, BFNone)
}

func (chain *Blockchain) ProcessTx(tx *massutil.Tx) (bool, error) {
	return chain.txPool.ProcessTransaction(tx, true, false)
}

func (chain *Blockchain) ChainID() *wire.Hash {
	return wire.NewHashFromHash(chain.info.chainID)
}

func (chain *Blockchain) GetTxPool() *TxPool {
	return chain.txPool
}

func (chain *Blockchain) BlockWaiter(height uint64) (<-chan *BlockNode, error) {
	chain.l.RLock()
	defer chain.l.RUnlock()

	if chain.blockTree.bestBlockNode().Height > height {
		return nil, errWaitForOldBlockHeight
	}

	ch := make(chan *BlockNode, 1)
	go func() {
		chain.cond.L.Lock()
		defer chain.cond.L.Unlock()
		var node *BlockNode
		for {
			chain.cond.Wait()
			node = chain.blockTree.bestBlockNode()
			if node.Height >= height {
				break
			}
		}
		ch <- node
		close(ch)
	}()

	return ch, nil
}

func (chain *Blockchain) RegisterListener(listener Listener) {
	chain.l.Lock()
	defer chain.l.Unlock()

	chain.listeners[listener] = struct{}{}
}

func (chain *Blockchain) UnregisterListener(listener Listener) {
	chain.l.Lock()
	defer chain.l.Unlock()

	delete(chain.listeners, listener)
}

func (chain *Blockchain) notifyBlockConnected(block *massutil.Block) error {
	if block == nil {
		return errNilArgument
	}
	for listener := range chain.listeners {
		err := listener.OnBlockConnected(block.MsgBlock())
		if err != nil {
			return err
		}
	}
	return nil
}

func (chain *Blockchain) notifyTransactionReceived(tx *massutil.Tx) error {
	if tx == nil {
		return errNilArgument
	}
	for listener := range chain.listeners {
		err := listener.OnTransactionReceived(tx.MsgTx())
		if err != nil {
			return err
		}
	}
	return nil
}

func (chain *Blockchain) CurrentIndexHeight() uint64 {
	return chain.blockTree.bestBlockNode().Height
}

// GetBlockStakingRewardRankOnList returns staking reward list at any height.
func (chain *Blockchain) GetBlockStakingRewardRankOnList(height uint64) ([]database.Rank, error) {
	if height == chain.BestBlockHeight() {
		return chain.db.FetchUnexpiredStakingRank(height, true)
	}
	return chain.db.FetchStakingRank(height, true)
}

// GetUnexpiredStakingRank returns all the unexpired staking rank.
func (chain *Blockchain) GetUnexpiredStakingRank(height uint64) ([]database.Rank, error) {
	return chain.db.FetchUnexpiredStakingRank(height, false)
}

func (chain *Blockchain) FetchOldBinding(scriptHash []byte) ([]*database.BindingTxReply, error) {
	return chain.db.FetchOldBinding(scriptHash)
}

func (chain *Blockchain) GetNewBinding(script []byte) (massutil.Amount, error) {
	if len(script) != txscript.OP_DATA_22 {
		return massutil.ZeroAmount(), fmt.Errorf("invalid new binding script length %d", len(script))
	}
	trie, err := chain.BestBlockNode().BindingState(chain.stateBindingDb)
	if err != nil {
		return massutil.ZeroAmount(), err
	}
	data, err := trie.TryGet(script)
	if err != nil {
		return massutil.ZeroAmount(), err
	}
	bi := state.DecodeBindingInfo(data)
	return massutil.NewAmountFromInt(bi.Amount)
}

func (chain *Blockchain) GetPoolPkCoinbase(poolPks [][]byte) (map[string]string, map[string]uint32, error) {
	poolPkToCoinbase := make(map[string]string)
	poolPkToNonce := make(map[string]uint32)
	trie, err := chain.BestBlockNode().BindingState(chain.stateBindingDb)
	if err != nil {
		return nil, nil, err
	}

	for _, poolPk := range poolPks {
		data, nonce, err := GetPoolPkCoinbase(trie, poolPk)
		if err != nil {
			return nil, nil, err
		}
		if len(data) != 0 {
			addr, err := massutil.NewAddressWitnessScriptHash(data, chain.chainParams)
			if err != nil {
				return nil, nil, err
			}
			poolPkToCoinbase[hex.EncodeToString(poolPk)] = addr.EncodeAddress()
			poolPkToNonce[hex.EncodeToString(poolPk)] = nonce
		} else {
			poolPkToCoinbase[hex.EncodeToString(poolPk)] = ""
			poolPkToNonce[hex.EncodeToString(poolPk)] = nonce
		}
	}
	return poolPkToCoinbase, poolPkToNonce, nil
}

func (chain *Blockchain) GetNetworkBinding(height uint64) (massutil.Amount, error) {
	block, err := chain.GetBlockByHeight(height)
	if err != nil {
		return massutil.MaxAmount(), err
	}

	var trie state.Trie
	if !forks.EnforceMASSIP0002WarmUp(block.Height()) {
		trie, err = chain.stateBindingDb.OpenBindingTrie(common.Hash{})
	} else {
		trie, err = chain.stateBindingDb.OpenBindingTrie(block.MsgBlock().Header.BindingRoot)
	}
	if err != nil {
		return massutil.MaxAmount(), err
	}
	return GetNetworkBinding(trie)
}
