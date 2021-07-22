package blockchain

import (
	"fmt"
	"time"

	"github.com/massnetorg/mass-core/blockchain/state"
	"github.com/massnetorg/mass-core/consensus/forks"
	"github.com/massnetorg/mass-core/logging"
	"github.com/massnetorg/mass-core/massutil"
	"github.com/massnetorg/mass-core/txscript"
	"github.com/massnetorg/mass-core/wire"
)

func (chain *Blockchain) maybeAcceptBlock(block *massutil.Block, flags BehaviorFlags) error {
	// Get a block node for the block previous to this one.  Will be nil
	// if this is the genesis block.
	prevNode, err := chain.getPrevNodeFromBlock(block)
	if err != nil {
		logging.CPrint(logging.ERROR, "fail on getPrevNodeFromBlock",
			logging.LogFormat{
				"err":     err,
				"preHash": block.MsgBlock().Header.Previous,
				"hash":    block.Hash(),
				"flags":   fmt.Sprintf("%b", flags),
			})
		return err
	}
	if prevNode == nil {
		logging.CPrint(logging.ERROR, "prev node not found",
			logging.LogFormat{
				"preHash": block.MsgBlock().Header.Previous,
				"hash":    block.Hash(),
				"flags":   fmt.Sprintf("%b", flags),
			})
		return fmt.Errorf("prev node not found")
	}

	// // The height of this block is one more than the referenced previous
	// // block.
	// block.SetHeight(prevNode.Height + 1)

	// The block must pass all of the validation rules which depend on the
	// position of the block within the block chain.
	err = chain.checkBlockContext(block, prevNode, flags)
	if err != nil {
		logging.CPrint(logging.ERROR, "fail on checkBlockContext",
			logging.LogFormat{
				"err": err, "preHash": block.MsgBlock().Header.Previous,
				"hash":  block.Hash(),
				"flags": fmt.Sprintf("%b", flags),
			})
		return err
	}

	// Create a new block node for the block and add it to the in-memory
	// block chain (could be either a side chain or the main chain).
	blockHeader := &block.MsgBlock().Header

	// if flags.isFlagSet(BFNoPoCCheck) {
	// 	return chain.checkConnectBlock(NewBlockNode(blockHeader, nil, BFNoPoCCheck), block)
	// }

	newNode := NewBlockNode(blockHeader, block.Hash(), BFNone)
	newNode.Parent = prevNode

	// Connect the passed block to the chain while respecting proper chain
	// selection according to the chain with the most proof of work.  This
	// also handles validation of the transaction scripts.
	err = chain.connectBestChain(newNode, block, flags)
	if err != nil {
		return err
	}

	return nil
}

func (chain *Blockchain) processOrphans(hash *wire.Hash, flags BehaviorFlags) error {
	for _, orphan := range chain.blockTree.orphanBlockPool.getOrphansByPrevious(hash) {
		logging.CPrint(logging.INFO, "process orphan",
			logging.LogFormat{
				"parent_hash":  hash,
				"child_hash":   orphan.block.Hash(),
				"child_height": orphan.block.Height(),
			})
		if err := chain.maybeAcceptBlock(orphan.block, BFNone); err != nil {
			chain.errCache.Add(orphan.block.Hash().String(), err)
			return err
		}

		chain.blockTree.orphanBlockPool.removeOrphanBlock(orphan)

		if err := chain.processOrphans(orphan.block.Hash(), BFNone); err != nil {
			return err
		}
	}

	return nil
}

// for importchain
func (chain *Blockchain) InsertChain(block *massutil.Block) (isOrphan bool, err error) {
	return chain.processBlock(block, BFNone)
}

func (chain *Blockchain) processBlock(block *massutil.Block, flags BehaviorFlags) (isOrphan bool, err error) {
	var startProcessing = time.Now()

	if flags.isFlagSet(BFNoPoCCheck) {
		return false, chain.checkConnectBlockTemplate(block, flags)
		// // Perform preliminary sanity checks on the block and its transactions.
		// err := checkBlockSanity(block, chain.info.chainID, chain.chainParams.PocLimit, flags)
		// if err != nil {
		// 	return false, err
		// }

		// // The block has passed all context independent checks and appears sane
		// // enough to potentially accept it into the block chain.
		// if err := chain.maybeAcceptBlock(block, flags); err != nil {
		// 	logging.CPrint(logging.ERROR, "fail on maybeAcceptBlock with BFNoPoCCheck", logging.LogFormat{
		// 		"err":      err,
		// 		"previous": block.MsgBlock().Header.Previous,
		// 		"height":   block.Height(),
		// 		"elapsed":  time.Since(startProcessing),
		// 		"flags":    fmt.Sprintf("%b", flags),
		// 	})
		// 	return false, err
		// }
		// return false, nil
	}

	blockHash := block.Hash()
	logging.CPrint(logging.TRACE, "processing block", logging.LogFormat{
		"hash":     blockHash,
		"height":   block.Height(),
		"tx_count": len(block.Transactions()),
		"flags":    fmt.Sprintf("%b", flags),
	})

	// The block must not already exist in the main chain or side chains.
	if chain.blockExists(blockHash) {
		return false, nil
	}

	// The block must not already exist as an orphan.
	if chain.blockTree.orphanExists(blockHash) {
		return true, nil
	}

	// Return fail if block error already been cached.
	if v, ok := chain.errCache.Get(blockHash.String()); ok {
		return false, v.(error)
	}

	// Perform preliminary sanity checks on the block and its transactions.
	err = checkBlockSanity(block, chain.info.chainID, chain.chainParams.PocLimit, flags)
	if err != nil {
		chain.errCache.Add(blockHash.String(), err)
		return false, err
	}

	blockHeader := &block.MsgBlock().Header
	checkpointNode, err := chain.findPreviousCheckpoint()
	if err != nil {
		return false, err
	}
	if checkpointNode != nil {
		// Ensure the block timestamp is after the checkpoint timestamp.
		if blockHeader.Timestamp.Before(checkpointNode.Timestamp) {
			return false, fmt.Errorf("%s: block %v has timestamp %v before "+
				"last checkpoint timestamp %v", ErrCheckpointTimeTooOld, blockHash,
				blockHeader.Timestamp, checkpointNode.Timestamp)
		}
	}

	// Handle orphan blocks.
	prevHash := &blockHeader.Previous
	if !prevHash.IsEqual(zeroHash) {
		prevHashExists := chain.blockExists(prevHash)

		if !prevHashExists {
			logging.CPrint(logging.INFO, "Adding orphan block with Parent", logging.LogFormat{
				"orphan":  blockHash,
				"height":  block.Height(),
				"parent":  prevHash,
				"elapsed": time.Since(startProcessing),
				"flags":   fmt.Sprintf("%b", flags),
			})
			chain.blockTree.orphanBlockPool.addOrphanBlock(block)
			return true, nil
		}
	}

	// The block has passed all context independent checks and appears sane
	// enough to potentially accept it into the block chain.
	if err := chain.maybeAcceptBlock(block, flags); err != nil {
		chain.errCache.Add(blockHash.String(), err)
		return false, err
	}

	// Accept any orphan blocks that depend on this block (they are
	// no longer orphans) and repeat for those accepted blocks until
	// there are no more.
	if err := chain.processOrphans(blockHash, flags); err != nil {
		return false, err
	}

	logging.CPrint(logging.DEBUG, "accepted block", logging.LogFormat{
		"hash":     blockHash,
		"height":   block.Height(),
		"tx_count": len(block.Transactions()),
		"elapsed":  time.Since(startProcessing),
		"flags":    fmt.Sprintf("%b", flags),
	})

	return false, nil
}

func (chain *Blockchain) checkConnectBlockTemplate(block *massutil.Block, flags BehaviorFlags) error {
	tip := chain.BestBlockNode()
	if *tip.Hash != block.MsgBlock().Header.Previous {
		return fmt.Errorf("previous block must be the current chain tip %v, "+
			"instead got %v", tip.Hash, block.MsgBlock().Header.Previous)
	}

	err := checkBlockSanity(block, chain.info.chainID, chain.chainParams.PocLimit, flags)
	if err != nil {
		logging.CPrint(logging.ERROR, "checkBlockSanity failed for block template", logging.LogFormat{"err": err, "height": block.Height()})
		return err
	}

	err = chain.checkBlockContext(block, tip, flags)
	if err != nil {
		logging.CPrint(logging.ERROR, "checkBlockContext failed in checkConnectBlockTemplate",
			logging.LogFormat{
				"err":    err,
				"tip":    block.MsgBlock().Header.Previous,
				"hash":   block.Hash(),
				"height": block.Height(),
			})
		return err
	}

	// Create a new block node for the block and add it to the in-memory
	// block chain (could be either a side chain or the main chain).
	blockHeader := &block.MsgBlock().Header
	node := NewBlockNode(blockHeader, nil, BFNoPoCCheck)
	if node.Parent, err = chain.getPrevNodeFromBlock(block); err != nil {
		logging.CPrint(logging.ERROR, "failed to load parent node for block template", logging.LogFormat{"err": err, "height": block.Height()})
		return err
	}
	if forks.EnforceMASSIP0002WarmUp(block.Height()) {
		txInputStore, err := chain.fetchInputTransactions(node, block)
		if err != nil {
			logging.CPrint(logging.ERROR, "failed to load inputs for block template", logging.LogFormat{"err": err, "height": block.Height()})
			return err
		}
		if err = chain.buildBlockTemplateBindingRoot(tip, block, txInputStore); err != nil {
			logging.CPrint(logging.ERROR, "failed to build binding root for block template", logging.LogFormat{"err": err, "height": block.Height()})
			return err
		}
	}

	if err = chain.checkConnectBlock(node, block, flags, nil); err != nil {
		logging.CPrint(logging.ERROR, "checkConnectBlock failed for block template", logging.LogFormat{"err": err, "height": block.Height()})
	}
	return err
}

func (chain *Blockchain) buildBlockTemplateBindingRoot(parent *BlockNode, newBlock *massutil.Block, txStore TxStore) error {
	newState, err := parent.BindingState(chain.stateBindingDb)
	if err != nil {
		return err
	}
	parentRoot := newState.Hash()

	networkBinding, err := GetNetworkBinding(newState)
	if err != nil {
		return err
	}
	oldNetworkBinding := networkBinding

	update := func(bindingScriptHash []byte, amount int64, isBind bool) error {
		buf, err := newState.TryGet(bindingScriptHash)
		if err != nil {
			return err
		}
		if !isBind {
			if buf == nil {
				return ErrPlotPKNotBound
			}
			if networkBinding, err = networkBinding.AddInt((-1) * amount); err != nil {
				return err
			}
			return newState.TryDelete(bindingScriptHash)
		}

		// bind
		if buf != nil {
			return ErrPlotPKAlreadyBound
		}
		if networkBinding, err = networkBinding.AddInt(amount); err != nil {
			return err
		}
		return newState.TryUpdate(bindingScriptHash, state.EncodeBindingInfo(&state.BindingInfo{
			Amount: amount,
		}))
	}

	bindingIn := 0
	bindingOut := 0

	for _, tx := range newBlock.Transactions() {
		if !IsCoinBase(tx) {
			for _, txIn := range tx.MsgTx().TxIn {
				prevTxData, exists := txStore[txIn.PreviousOutPoint.Hash]
				if !exists || prevTxData.Err != nil || prevTxData.Tx == nil {
					return ErrMissingTx
				}

				prevTx := prevTxData.Tx.MsgTx()

				if !forks.EnforceMASSIP0002WarmUp(prevTxData.BlockHeight) {
					continue
				}

				bindingScriptHash, err := TryParserBindingPK(prevTx.TxOut[txIn.PreviousOutPoint.Index].PkScript)
				if err != nil {
					return err
				}
				if bindingScriptHash == nil {
					continue
				}
				if len(bindingScriptHash) != txscript.OP_DATA_22 {
					return ErrInvalidBindingScript
				}
				bindingIn++
				if err = update(bindingScriptHash, prevTx.TxOut[txIn.PreviousOutPoint.Index].Value, false); err != nil {
					return err
				}
			}
		}

		// output
		for _, txOut := range tx.MsgTx().TxOut {
			bindingScriptHash, err := TryParserBindingPK(txOut.PkScript)
			if err != nil {
				return err
			}
			if bindingScriptHash == nil {
				continue
			}
			if len(bindingScriptHash) != txscript.OP_DATA_22 {
				return ErrInvalidBindingScript
			}
			bindingOut++
			if err = update(bindingScriptHash, txOut.Value, true); err != nil {
				return err
			}
		}

		// payload
		if !IsCoinBase(tx) {
			if err := CheckNonceAndSetPoolPkCoinbase(newState, tx.MsgTx().Payload); err != nil {
				logging.CPrint(logging.ERROR, "failed to put pool pk coinbase", logging.LogFormat{
					"block":  newBlock.Hash(),
					"height": newBlock.Height(),
					"tx":     tx.Hash(),
					"err":    err,
				})
				return err
			}
		}
	}

	if oldNetworkBinding.Cmp(networkBinding) != 0 {
		if err := PutNetworkBinding(newState, networkBinding); err != nil {
			return err
		}
	}

	newBlock.MsgBlock().Header.BindingRoot = newState.Hash()

	logging.CPrint(logging.INFO, "buildBlockTemplateBindingRoot", logging.LogFormat{
		"parent":            parent.Hash,
		"parentBindingRoot": parentRoot,
		"newHeight":         newBlock.Height(),
		"newBindingRoot":    newBlock.MsgBlock().Header.BindingRoot,
		"totalTxs":          len(newBlock.Transactions()),
		"bindingIn":         bindingIn,
		"bindingOut":        bindingOut,
	})
	return nil
}
