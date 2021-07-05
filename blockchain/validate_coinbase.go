package blockchain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/massnetorg/mass-core/config"
	"github.com/massnetorg/mass-core/consensus/forks"
	"github.com/massnetorg/mass-core/database"
	"github.com/massnetorg/mass-core/logging"
	"github.com/massnetorg/mass-core/massutil"
	"github.com/massnetorg/mass-core/poc"
	"github.com/massnetorg/mass-core/txscript"
)

func (chain *Blockchain) validateCoinbase(
	block *massutil.Block,
	node *BlockNode,
	txInputStore TxStore,
	totalFees massutil.Amount,
	net *config.Params,
) (err error) {

	coinbaseTx := block.Transactions()[0]
	header := &block.MsgBlock().Header
	bindingTarget, err := pkToScriptHash(header.PublicKey().SerializeCompressed(), net)
	if err != nil {
		return err
	}

	// fetch binding transactions from database
	stakingTx, err := chain.fetchStakingTxStore(node)
	if err != nil {
		logging.CPrint(logging.ERROR, "Failed to fetch stakingTx",
			logging.LogFormat{
				"stakingTx": stakingTx,
				"error":     err,
			})
		return err
	}

	//     |--------- mass binding before massip2 warmup -------|---------- no binding and only mass miner before massip2 ------|------ binding required ------|
	hasValidBinding := false
	if !forks.EnforceMASSIP0002WarmUp(block.Height()) {
		totalBinding, err := checkCoinbaseInputs(coinbaseTx, txInputStore, bindingTarget, net, node.Height)
		if err != nil {
			return err
		}
		requiredBinding, err := forks.GetRequiredBinding(block.Height(), 0, node.BitLength(), massutil.ZeroAmount())
		if err != nil {
			return err
		}
		hasValidBinding = totalBinding.Cmp(requiredBinding) >= 0

	} else if forks.EnforceMASSIP0002(block.Height()) {
		parentBindingState, err := node.ParentBindingState(chain.stateBindingDb)
		if err != nil {
			return err
		}

		// Check chia header if coinbase address is the one bound to pool pk.
		if header.Proof.Type() == poc.ProofTypeChia {
			poolPk, err := poc.GetChiaPoolPublicKey(header.Proof)
			if err != nil {
				return err
			}
			if poolPk == nil {
				// TODO: Now pool pk must be present.
				return ErrNilChiaPoolPk
			}
			coinbaseScriptAddress, _, err := GetPoolPkCoinbase(parentBindingState, poolPk.Bytes())
			if err != nil {
				return err
			}
			if len(coinbaseScriptAddress) != 0 {
				script, err := txscript.PayToWitnessScriptHashScript(coinbaseScriptAddress)
				if err != nil {
					return err
				}
				if !bytes.Equal(script, coinbaseTx.MsgTx().TxOut[len(coinbaseTx.MsgTx().TxOut)-1].PkScript) {
					logging.CPrint(logging.WARN, "receive block with inconsistent coinbase",
						logging.LogFormat{
							"height": block.Height(),
							"block":  block.Hash(),
							"expect": hex.EncodeToString(script),
							"actual": hex.EncodeToString(coinbaseTx.MsgTx().TxOut[len(coinbaseTx.MsgTx().TxOut)-1].PkScript),
						})
					return ErrUnexpectedCoinbase
				}
			}

			// Target of chia binding is plot ID
			plotID, err := poc.GetChiaPlotID(header.Proof)
			if err != nil {
				logging.CPrint(logging.WARN, "get chia plot ID error", logging.LogFormat{"err": err})
				return err
			}
			if plotID == [32]byte{} {
				logging.CPrint(logging.ERROR, "zero plot ID")
				return fmt.Errorf("zero plot ID")
			}
			if bindingTarget, err = pkToScriptHash(plotID[:], net); err != nil {
				return err
			}
		}

		// check binding amount
		bindingTarget = append(bindingTarget, byte(header.Proof.Type()), byte(header.Proof.BitLength()))
		data, err := parentBindingState.TryGet(bindingTarget)
		if err != nil {
			return err
		}
		if data == nil {
			// Disallow minting without binding
			return ErrPlotPKNotBound
		}
		hasValidBinding = true
	}

	totalreward, err := checkCoinbase(coinbaseTx, stakingTx, node, hasValidBinding, net)
	if err != nil {
		return err
	}
	maxTotalCoinbaseOut, err := totalreward.Add(totalFees)
	if err != nil {
		return err
	}

	// The total output values of the coinbase transaction must not exceed
	// the expected subsidy value plus total transaction fees gained from
	// mining the block.  It is safe to ignore overflow and out of range
	// errors here because those error conditions would have already been
	// caught by checkTransactionSanity.
	totalCoinbaseOut := massutil.ZeroAmount()
	for _, txOut := range coinbaseTx.MsgTx().TxOut {
		totalCoinbaseOut, err = totalCoinbaseOut.AddInt(txOut.Value)
		if err != nil {
			return err
		}
	}

	if totalCoinbaseOut.Cmp(maxTotalCoinbaseOut) > 0 {
		logging.CPrint(logging.ERROR, "incorrect total output value",
			logging.LogFormat{
				"actual": totalCoinbaseOut,
				"expect": maxTotalCoinbaseOut,
			})
		return ErrBadCoinbaseValue
	}

	return nil
}

func checkCoinbaseInputs(
	coinbaseTx *massutil.Tx,
	txStore TxStore,
	headerPkHash []byte,
	net *config.Params,
	nextBlockHeight uint64,
) (massutil.Amount, error) {
	totalMaxwellIn := massutil.ZeroAmount()
	for _, txIn := range coinbaseTx.MsgTx().TxIn[1:] {
		txInHash := txIn.PreviousOutPoint.Hash
		originTxIndex := txIn.PreviousOutPoint.Index
		originTx, exists := txStore[txInHash]
		if !exists || originTx.Err != nil || originTx.Tx == nil {
			logging.CPrint(logging.ERROR, "unable to find input transaction for coinbaseTx",
				logging.LogFormat{"height": nextBlockHeight, "txInIndex": originTxIndex, "txInHash": txInHash})
			return massutil.ZeroAmount(), ErrMissingTx
		}
		mtx := originTx.Tx.MsgTx()

		err := checkTxInMaturity(originTx, nextBlockHeight, txIn.PreviousOutPoint, true)
		if err != nil {
			return massutil.ZeroAmount(), err
		}

		err = checkDupSpend(txIn.PreviousOutPoint, originTx.Spent)
		if err != nil {
			return massutil.ZeroAmount(), err
		}

		originTxMaxwell, err := massutil.NewAmountFromInt(originTx.Tx.MsgTx().TxOut[originTxIndex].Value)
		if err != nil {
			logging.CPrint(logging.ERROR, "invalid coinbase input value",
				logging.LogFormat{
					"blkHeight": nextBlockHeight,
					"prevTx":    txInHash.String(),
					"prevIndex": originTxIndex,
					"value":     originTx.Tx.MsgTx().TxOut[originTxIndex].Value,
					"err":       err,
				})
			return massutil.ZeroAmount(), err
		}

		totalMaxwellIn, err = totalMaxwellIn.Add(originTxMaxwell)
		if err != nil {
			logging.CPrint(logging.ERROR, "calc coinbase total input value error",
				logging.LogFormat{
					"height": nextBlockHeight,
					"tx":     coinbaseTx.Hash(),
					"err":    err,
				})
			return massutil.ZeroAmount(), err
		}

		class, pops := txscript.GetScriptInfo(mtx.TxOut[originTxIndex].PkScript)
		if class != txscript.BindingScriptHashTy {
			logging.CPrint(logging.ERROR, "coinbase input is not a binding transaction output",
				logging.LogFormat{"blkHeight": nextBlockHeight, "pkScript": mtx.TxOut[originTxIndex].PkScript, "class": class})
			return massutil.ZeroAmount(), ErrBindingPubKey
		}

		_, bindingScriptHash, err := txscript.GetParsedBindingOpcode(pops)
		if err != nil {
			return massutil.ZeroAmount(), err
		}
		if len(bindingScriptHash) != txscript.OP_DATA_20 {
			return massutil.ZeroAmount(), ErrInvalidBindingScript
		}

		if !bytes.Equal(headerPkHash, bindingScriptHash) {
			logging.CPrint(logging.ERROR, "binding pubkey does not match miner pubkey",
				logging.LogFormat{"blkHeight": nextBlockHeight, "pubkeyScript": bindingScriptHash, "expected": headerPkHash})
			return massutil.ZeroAmount(), ErrBindingPubKey
		}
	}
	return totalMaxwellIn, nil
}

//checkCoinbase checks the outputs of coinbase
func checkCoinbase(tx *massutil.Tx, stakingRanks []database.Rank, node *BlockNode, hasValidBinding bool, net *config.Params) (massutil.Amount, error) {
	nextBlockHeight := node.Height

	num := len(stakingRanks)
	StakingRewardNum, err := extractCoinbaseStakingRewardNumber(tx)
	if err != nil {
		return massutil.ZeroAmount(), err
	}
	if StakingRewardNum > uint32(num) {
		return massutil.ZeroAmount(), ErrStakingRewardNum
	}

	miner, superNode, err := CalcBlockSubsidy(nextBlockHeight, net, hasValidBinding, num > 0)
	if err != nil {
		return massutil.ZeroAmount(), err
	}

	stakingNodes := make([]forks.StakingNode, 0, len(stakingRanks))
	for _, snode := range stakingRanks {
		stakingNodes = append(stakingNodes, snode)
	}
	totalWeight, err := forks.CalcTotalStakingWeight(nextBlockHeight, stakingNodes...)
	if err != nil {
		return massutil.ZeroAmount(), err
	}

	i := 0
	for ; i < num; i++ {
		nodeWeight, err := forks.CalcStakingNodeWeight(nextBlockHeight, stakingRanks[i])
		if err != nil {
			return massutil.ZeroAmount(), err
		}
		expectAmount, err := calcNodeReward(superNode, totalWeight, nodeWeight)
		if err != nil {
			return massutil.ZeroAmount(), err
		}

		if expectAmount.IsZero() {
			break
		}

		// check value
		if expectAmount.IntValue() != tx.MsgTx().TxOut[i].Value {
			logging.CPrint(logging.ERROR, "incorrect reward value for stakingTxs",
				logging.LogFormat{
					"block height": nextBlockHeight,
					"index":        i,
					"actual":       tx.MsgTx().TxOut[i].Value,
					"expect":       expectAmount,
				})
			return massutil.ZeroAmount(), errors.New("incorrect reward value for stakingTxs")
		}

		// check pkscript
		key := make([]byte, sha256.Size)
		copy(key, stakingRanks[i].ScriptHash[:])
		pkScriptSuperNode, err := txscript.PayToWitnessScriptHashScript(key)
		if err != nil {
			return massutil.ZeroAmount(), err
		}
		if !bytes.Equal(tx.MsgTx().TxOut[i].PkScript, pkScriptSuperNode) {
			class, pops := txscript.GetScriptInfo(tx.MsgTx().TxOut[i].PkScript)
			_, rsh, err := txscript.GetParsedOpcode(pops, class)
			if err != nil {
				return massutil.ZeroAmount(), err
			}
			logging.CPrint(logging.ERROR, "The reward address for stakingTxs is wrong",
				logging.LogFormat{
					"block height":          nextBlockHeight,
					"index":                 i,
					"stakingTxs scriptHash": key,
					"txout scriptHash":      rsh,
				})
			return massutil.ZeroAmount(), errors.New("incorrect reward address for stakingTxs")
		}
	}
	if uint32(i) != StakingRewardNum {
		logging.CPrint(logging.ERROR, "Mismatched staking reward number",
			logging.LogFormat{
				"block height": nextBlockHeight,
				"expect":       StakingRewardNum,
				"actual":       i,
			})
		return massutil.ZeroAmount(), ErrStakingRewardNum
	}

	// No need to check miner reward ouput, because the caller will check total reward+fee
	return miner.Add(superNode)
}
