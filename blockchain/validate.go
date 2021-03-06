package blockchain

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/massnetorg/mass-core/blockchain/state"
	"github.com/massnetorg/mass-core/config"
	"github.com/massnetorg/mass-core/consensus"
	"github.com/massnetorg/mass-core/consensus/forks"
	"github.com/massnetorg/mass-core/database"
	"github.com/massnetorg/mass-core/interfaces"
	"github.com/massnetorg/mass-core/logging"
	"github.com/massnetorg/mass-core/massutil"
	"github.com/massnetorg/mass-core/poc"
	"github.com/massnetorg/mass-core/poc/pocutil"
	"github.com/massnetorg/mass-core/txscript"
	"github.com/massnetorg/mass-core/wire"
)

const (
	// MaxSigOpsPerBlock is the maximum number of signature operations
	// allowed for a block.  It is a fraction of the max block payload size.
	MaxSigOpsPerBlock = wire.MaxBlockPayload / 150 * txscript.MaxPubKeysPerMultiSig

	// MaxTimeOffsetSeconds is the maximum number of seconds a block time
	// is allowed to be ahead of the current time.  This is currently 2
	// hours.
	MaxTimeOffsetSeconds = 2 * 60 * 60

	// medianTimeBlocks is the number of previous blocks which should be
	// used to calculate the median time used to validate block timestamps.
	medianTimeBlocks = 11
)

var (
	// zeroHash is the zero value for a wire.Hash and is defined as
	// a package level variable to avoid the need to create a new instance
	// every time a check is needed.
	zeroHash = &wire.Hash{}
)

// isNullOutpoint determines whether or not a previous transaction output point
// is set.
func isNullOutpoint(outpoint *wire.OutPoint) bool {
	if outpoint.Index == math.MaxUint32 && outpoint.Hash.IsEqual(zeroHash) {
		return true
	}
	return false
}

// IsCoinBaseTx determines whether or not a transaction is a coinbase.  A coinbase
// is a special transaction created by miners that has no inputs.  This is
// represented in the block chain by a transaction with a single input that has
// a previous output transaction index set to the maximum value along with a
// zero hash.
//
// This function only differs from IsCoinBase in that it works with a raw wire
// transaction as opposed to a higher level util transaction.
func IsCoinBaseTx(msgTx *wire.MsgTx) bool {
	// A coin base must only have one transaction input.
	if len(msgTx.TxIn) < 1 {
		return false
	}

	// The previous output of a coin base must have a max value index and
	// a zero hash.
	prevOut := &msgTx.TxIn[0].PreviousOutPoint
	if prevOut.Index != math.MaxUint32 || !prevOut.Hash.IsEqual(zeroHash) {
		return false
	}

	return true
}

// IsCoinBase determines whether or not a transaction is a coinbase.  A coinbase
// is a special transaction created by miners that has no inputs.  This is
// represented in the block chain by a transaction with a single input that has
// a previous output transaction index set to the maximum value along with a
// zero hash.
//
// This function only differs from IsCoinBaseTx in that it works with a higher
// level util transaction as opposed to a raw wire transaction.
func IsCoinBase(tx *massutil.Tx) bool {
	return IsCoinBaseTx(tx.MsgTx())
}

func pkToScriptHash(pubKey []byte, net *config.Params) ([]byte, error) {
	addressPubKeyHash, err := massutil.NewAddressPubKeyHash(massutil.Hash160(pubKey), net)
	if err != nil {
		return nil, err
	}
	return addressPubKeyHash.ScriptAddress(), nil
}

// for poc pk
func pkToRedeemScriptHash(pubkey []byte, net *config.Params) ([]byte, error) {
	var addressPubKeyStructs []*massutil.AddressPubKey
	addressPubKeyStruct, err := massutil.NewAddressPubKey(pubkey, net)
	if err != nil {
		return nil, err
	}
	addressPubKeyStructs = append(addressPubKeyStructs, addressPubKeyStruct)
	redeemScript, err := txscript.MultiSigScript(addressPubKeyStructs, 1)
	if err != nil {
		return nil, err
	}
	scriptHash := massutil.Hash160(redeemScript)
	return scriptHash, nil
}

// SequenceLockActive determines if a transaction's sequence locks have been
// met, meaning that all the inputs of a given transaction have reached a
// height or time sufficient for their relative lock-time maturity.
func SequenceLockActive(sequenceLock *SequenceLock, blockHeight uint64,
	medianTimePast time.Time) bool {

	// If either the seconds, or height relative-lock time has not yet
	// reached, then the transaction is not yet mature according to its
	// sequence locks.
	if sequenceLock.Seconds >= medianTimePast.Unix() ||
		sequenceLock.BlockHeight >= blockHeight {
		return false
	}

	return true
}

// IsFinalizedTransaction determines whether or not a transaction is finalized.
func IsFinalizedTransaction(tx *massutil.Tx, blockHeight uint64, blockTime time.Time) bool {
	msgTx := tx.MsgTx()

	// Lock time of zero means the transaction is finalized.
	lockTime := msgTx.LockTime
	if lockTime == 0 {
		return true
	}

	// The lock time field of a transaction is either a block height at
	// which the transaction is finalized or a timestamp depending on if the
	// value is before the txscript.LockTimeThreshold.  When it is under the
	// threshold it is a block height.
	var blockTimeOrHeight int64
	if lockTime < txscript.LockTimeThreshold {
		blockTimeOrHeight = int64(blockHeight)
	} else {
		blockTimeOrHeight = blockTime.Unix()
	}
	if int64(lockTime) < blockTimeOrHeight {
		return true
	}

	// At this point, the transaction's lock time hasn't occured yet, but
	// the transaction might still be finalized if the sequence number
	// for all transaction inputs is maxed out.
	for _, txIn := range msgTx.TxIn {
		if txIn.Sequence != wire.MaxTxInSequenceNum {
			return false
		}
	}
	return true
}

// CheckTransactionSanity performs some preliminary checks on a transaction to
// ensure it is sane.  These checks are context free.
func CheckTransactionSanity(tx *massutil.Tx) error {
	// A transaction must have at least one input.
	msgTx := tx.MsgTx()
	if len(msgTx.TxIn) == 0 {
		return ErrNoTxInputs
	}

	// A transaction must have at least one output.
	if len(msgTx.TxOut) == 0 {
		return ErrNoTxOutputs
	}

	// A transaction must not exceed the maximum allowed block payload when
	// serialized.

	//witness
	// serializedTxSize := tx.MsgTx().PlainSize()
	serializedTxSize := tx.MsgTx().PlainSize()

	// if serializedTxSize > wire.MaxBlockPayload
	if serializedTxSize > wire.MaxBlockPayload {
		logging.CPrint(logging.ERROR, "transaction size is too big",
			logging.LogFormat{"txSize": serializedTxSize, "txSizeLimit": wire.MaxBlockPayload})
		return ErrTxTooBig
	}

	// Ensure the transaction amounts are in range.  Each transaction
	// output must not be negative or more than the max allowed per
	// transaction.  Also, the total of all outputs must abide by the same
	// restrictions.  All amounts in a transaction are in a unit value known
	// as a maxwell.  One Mass is a quantity of maxwell as defined by the
	// MaxwellPerMass constant.
	var err error
	totalMaxwell := massutil.ZeroAmount()
	for i, txOut := range msgTx.TxOut {
		totalMaxwell, err = totalMaxwell.AddInt(txOut.Value)
		if err != nil {
			logging.CPrint(logging.ERROR, "count total output failed",
				logging.LogFormat{
					"index": i,
					"value": txOut.Value,
					"total": totalMaxwell,
					"limit": massutil.MaxAmount().Value(),
					"err":   err,
				})
			return ErrBadTxOutValue
		}
	}

	// Check for duplicate transaction inputs.
	existingTxOut := make(map[wire.OutPoint]struct{})
	for _, txIn := range msgTx.TxIn {
		if _, exists := existingTxOut[txIn.PreviousOutPoint]; exists {
			return ErrDuplicateTxInputs
		}
		existingTxOut[txIn.PreviousOutPoint] = struct{}{}
	}

	// Coinbase script length must be between min and max length.
	if IsCoinBase(tx) {
		for _, txIn := range msgTx.TxIn[1:] {
			prevOut := &txIn.PreviousOutPoint
			if isNullOutpoint(prevOut) {
				return ErrBadTxInput
			}
		}
	} else {
		// Previous transaction outputs referenced by the inputs to this
		// transaction must not be null.
		for _, txIn := range msgTx.TxIn {
			prevOut := &txIn.PreviousOutPoint
			if isNullOutpoint(prevOut) {
				return ErrBadTxInput
			}
		}
	}

	return nil
}

// checkProofOfCapacity ensures the block header Target
// is in min/max range and that the block's proof quality is less than the
// Target difficulty as claimed.
func checkProofOfCapacity(header *wire.BlockHeader, pocLimit *big.Int) error {
	// match proof type with header version
	if !forks.EnforceMASSIP0002(header.Height) && header.Proof.Type() != poc.ProofTypeDefault {
		return ErrInvalidProofType
	}

	// The Target difficulty must be larger than zero.
	target := header.Target
	if target.Sign() <= 0 {
		logging.CPrint(logging.ERROR, "block Target difficulty is too low",
			logging.LogFormat{"target": target})
		return ErrUnexpectedDifficulty
	}

	// The Target difficulty must be less than the maximum allowed.
	if target.Cmp(pocLimit) < 0 {
		logging.CPrint(logging.ERROR, "block Target difficulty is lower than min of pocLimit",
			logging.LogFormat{"target": target, "pocLimit": pocLimit})
		return ErrUnexpectedDifficulty
	}

	logging.CPrint(logging.TRACE, "validate: check PoC", logging.LogFormat{
		"timestamp":  uint64(header.Timestamp.Unix()),
		"height":     header.Height,
		"big_length": header.Proof.BitLength(),
		"challenge":  header.Challenge,
	})

	pubKeyHash := pocutil.PubKeyItfHash(header.PubKey)
	slot := uint64(header.Timestamp.Unix()) / poc.PoCSlot
	quality, err := header.Proof.VerifiedQuality(pubKeyHash, pocutil.Hash(header.Challenge), forks.EnforceMASSIP0002(header.Height), slot, header.Height)
	if err != nil {
		return err
	}
	if quality.Cmp(target) < 0 {
		logging.CPrint(logging.ERROR, "block's proof quality is lower than expected min target",
			logging.LogFormat{"quality": quality, "expected": target, "height": header.Height, "hash": header.BlockHash()})
		return ErrLowQuality
	}

	return nil
}

// CheckProofOfWork ensures the block header bits which indicate the Target
// difficulty is in min/max range and that the block's proof quality is less than the
// Target difficulty as claimed.
func CheckProofOfCapacity(block *massutil.Block, pocLimit *big.Int) error {
	return checkProofOfCapacity(&block.MsgBlock().Header, pocLimit)
}

func checkChainID(header *wire.BlockHeader, chainID wire.Hash) error {
	if !header.ChainID.IsEqual(&chainID) {
		logging.CPrint(logging.ERROR, "block's chainID is not equal to expected chainID",
			logging.LogFormat{"block chainID": header.ChainID.String(), "expected": chainID.String()})

		return ErrChainID
	}
	return nil
}

func checkVersion(header *wire.BlockHeader) error {
	requiredVersion := forks.GetBlockVersion(header.Height)
	if header.Version < requiredVersion {
		logging.CPrint(logging.ERROR, "invalid block version",
			logging.LogFormat{"err": ErrInvalidBlockVersion, "block_version": header.Version, "required_version": requiredVersion})
		return ErrInvalidBlockVersion
	}
	return nil
}

func checkHeaderTimestamp(header *wire.BlockHeader) error {
	// A block timestamp must not have a greater precision than one second.
	// This check is necessary because Go time.Time values support
	// nanosecond precision whereas the consensus rules only apply to
	// seconds and it's much nicer to deal with standard Go time values
	// instead of converting to seconds everywhere.
	if !header.Timestamp.Equal(time.Unix(header.Timestamp.Unix(), 0)) {

		logging.CPrint(logging.ERROR, "block timestamp has a higher precision the one second",
			logging.LogFormat{"timestamp": header.Timestamp})
		return ErrInvalidTime
	}

	allowed := time.Now().Add(3 * time.Second)
	if allowed.Before(header.Timestamp) {
		logging.CPrint(logging.ERROR, "block timestamp of unix is too far in the future",
			logging.LogFormat{
				"allowed":        allowed.Unix(),
				"timestamp_unix": header.Timestamp.Unix(),
				"timestamp":      header.Timestamp.Format(time.RFC3339),
				"height":         header.Height,
				"block":          header.BlockHash(),
			})
		return ErrTimeTooNew
	}

	return nil
}

func checkHeaderBanList(header *wire.BlockHeader) error {
	dupPk := make(map[string]struct{})
	hpk := header.PublicKey().SerializeCompressed()
	for _, bpk := range header.BannedPublicKeys() {
		if bytes.Equal(hpk, bpk.SerializeCompressed()) {
			logging.CPrint(logging.ERROR, "block's pubKey is banned in header banList",
				logging.LogFormat{"pubkey": hex.EncodeToString(hpk)})
			return ErrBanSelfPk
		}
		strPk := hex.EncodeToString(bpk.SerializeCompressed())
		if _, exists := dupPk[strPk]; exists {
			logging.CPrint(logging.ERROR, "duplicate pubKey in header banList")
			return ErrBanList
		}
		dupPk[strPk] = struct{}{}
	}
	return nil
}

// checkHeaderSignature checks the signature in blockHeader
func checkHeaderSignature(header *wire.BlockHeader) error {
	if header.Signature == nil || header.PubKey == nil {
		logging.CPrint(logging.ERROR, "block signature verify failed for nil sig or pk")
		return ErrBlockSIG
	}

	correct, err := header.VerifySig()
	if err != nil {
		return err
	}
	if !correct {
		logging.CPrint(logging.ERROR, "block signature verify failed")
		return ErrBlockSIG
	}
	return nil
}

// CountSigOps returns the number of signature operations for all transaction
//// input and output scripts in the provided transaction.  This uses the
//// quicker, but imprecise, signature operation counting mechanism from
//// txscript.
func CountSigOps(tx *massutil.Tx) int {
	msgTx := tx.MsgTx()
	if IsCoinBaseTx(msgTx) {
		return 0
	}
	totalSigOps := 0

	for _, txIn := range msgTx.TxIn {
		numSigOps := txscript.GetSigOpCount(txIn.Witness[len(txIn.Witness)-1])
		totalSigOps += numSigOps
	}
	//}

	// Accumulate the number of signature operations in all transaction
	// inputs.

	// Accumulate the number of signature operations in all transaction
	// outputs.
	for _, txOut := range msgTx.TxOut {
		numSigOps := txscript.GetSigOpCount(txOut.PkScript)
		totalSigOps += numSigOps
		//log.Warn("the numsig is :",totalSigOps)
	}

	return totalSigOps
}

// checkBlockHeaderSanity performs some preliminary checks on a block header to
// ensure it is sane before continuing with processing.  These checks are
// context free.
//
// The flags do not modify the behavior of this function directly, however they
// are needed to pass along to checkProofOfWork.
func checkBlockHeaderSanity(header *wire.BlockHeader, chainID wire.Hash, pocLimit *big.Int, flags BehaviorFlags) (err error) {
	err = checkChainID(header, chainID)
	if err != nil {
		return
	}

	err = checkVersion(header)
	if err != nil {
		return
	}

	err = checkHeaderTimestamp(header)
	if err != nil {
		return
	}

	err = checkHeaderBanList(header)
	if err != nil {
		return
	}

	err = checkProofOfCapacity(header, pocLimit)
	if err != nil {
		return err
	}

	err = checkHeaderSignature(header)
	if err != nil {
		return err
	}

	return nil
}

// checkBlockSanity performs some preliminary checks on a block to ensure it is
// sane before continuing with block processing.  These checks are context free.
func checkBlockSanity(block *massutil.Block, chainID wire.Hash, pocLimit *big.Int, flags BehaviorFlags) error {
	msgBlock := block.MsgBlock()
	header := &msgBlock.Header
	proposals := &msgBlock.Proposals

	if !flags.isFlagSet(BFNoPoCCheck) {
		if err := checkBlockHeaderSanity(header, chainID, pocLimit, flags); err != nil {
			return err
		}
	}

	if err := checkBlockProposalSanity(proposals, header, chainID); err != nil {
		return err
	}

	// A block must have at least one transaction.
	numTx := len(msgBlock.Transactions)
	if numTx == 0 {
		return errBlockNoTransactions
	}

	// Checks that coinbase height matches block header height.
	if err := CheckCoinbaseHeight(block); err != nil {
		return err
	}

	// A block must not have more transactions than the max block payload.
	if numTx > wire.MaxTxPerBlock {
		logging.CPrint(logging.ERROR, "block contains too many transactions",
			logging.LogFormat{"numTx": numTx, "MaxTxPerBlock": wire.MaxTxPerBlock})
		return ErrTooManyTransactions
	}

	// A block must not exceed the maximum allowed block payload when
	// serialized.
	//serializedSize := msgBlock.PlainSize()
	serializedSize := msgBlock.PlainSize()
	//if serializedSize > wire.MaxBlockPayload
	if serializedSize > wire.MaxBlockPayload {
		logging.CPrint(logging.ERROR, "serialized block is too big",
			logging.LogFormat{"serializedSize": serializedSize, "MaxBlockPayload": wire.MaxBlockPayload})
		return ErrBlockTooBig
	}

	// ProposalRoot check
	proposalMerkles := wire.BuildMerkleTreeStoreForProposal(&block.MsgBlock().Proposals)
	calculatedProposalRoot := proposalMerkles[len(proposalMerkles)-1]
	if !header.ProposalRoot.IsEqual(calculatedProposalRoot) {
		logging.CPrint(logging.ERROR, "block proposal root is invalid",
			logging.LogFormat{"header.ProposalRoot": header.ProposalRoot, "calculate": calculatedProposalRoot})
		return ErrInvalidProposalRoot
	}

	// The first transaction in a block must be a coinbase.
	transactions := block.Transactions()
	if !IsCoinBase(transactions[0]) {
		return ErrFirstTxNotCoinbase
	}

	// A block must not have more than one coinbase.
	for i, tx := range transactions[1:] {
		if IsCoinBase(tx) {
			logging.CPrint(logging.ERROR, "block contains other coinbase",
				logging.LogFormat{"hindex": i})
			return ErrMultipleCoinbases
		}
	}

	// Do some preliminary checks on each transaction to ensure they are
	// sane before continuing.
	for _, tx := range transactions {
		err := CheckTransactionSanity(tx)
		if err != nil {
			return err
		}
	}

	// Build merkle tree and ensure the calculated merkle root matches the
	// entry in the block header.  This also has the effect of caching all
	// of the transaction hashes in the block to speed up future hash
	// checks.  Massd builds the tree here and checks the merkle root
	// after the following checks, but there is no reason not to check the
	// merkle root matches here.
	merkles := wire.BuildMerkleTreeStoreTransactions(block.MsgBlock().Transactions, false)
	calculatedMerkleRoot := merkles[len(merkles)-1]
	if !header.TransactionRoot.IsEqual(calculatedMerkleRoot) {
		logging.CPrint(logging.ERROR, "block merkle root is invalid",
			logging.LogFormat{"header.TransactionRoot": header.TransactionRoot, "calculate": calculatedMerkleRoot})
		return ErrInvalidMerkleRoot
	}

	witnessMerkles := wire.BuildMerkleTreeStoreTransactions(block.MsgBlock().Transactions, true)
	witnessMerkleRoot := witnessMerkles[len(witnessMerkles)-1]
	if !header.WitnessRoot.IsEqual(witnessMerkleRoot) {
		logging.CPrint(logging.ERROR, "block witness merkle root is invalid",
			logging.LogFormat{"header.WitnessRoot": header.WitnessRoot, "calculate": witnessMerkleRoot})
		return ErrInvalidMerkleRoot
	}

	// Check for duplicate transactions.  This check will be fairly quick
	// since the transaction hashes are already cached due to building the
	// merkle tree above.
	existingTxHashes := make(map[wire.Hash]struct{})
	for i, tx := range transactions {
		hash := tx.Hash()
		if _, exists := existingTxHashes[*hash]; exists {
			logging.CPrint(logging.ERROR, "block contains duplicate transaction",
				logging.LogFormat{"transaction": hash, "index": i})
			return ErrDuplicateTx
		}
		existingTxHashes[*hash] = struct{}{}
	}

	// The number of signature operations must be less than the maximum
	// allowed per block.
	totalSigOps := 0
	for _, tx := range transactions {
		// We could potentially overflow the accumulator so check for
		// overflow.
		lastSigOps := totalSigOps

		//witness-totalSigOps += CountSigOps(tx)
		totalSigOps += CountSigOps(tx)
		if totalSigOps < lastSigOps || totalSigOps > MaxSigOpsPerBlock {
			logging.CPrint(logging.ERROR, "block contains too many signature operations",
				logging.LogFormat{"totalSigOps": totalSigOps, "maxSigOps": MaxSigOpsPerBlock})
			return ErrTooManySigOps
		}
	}

	return nil
}

// CheckBlockSanity performs some preliminary checks on a block to ensure it is
// sane before continuing with block processing.  These checks are context free.
func CheckBlockSanity(block *massutil.Block, chainID wire.Hash, pocLimit *big.Int) error {
	return checkBlockSanity(block, chainID, pocLimit, BFNone)
}

// checkBlockHeaderContext peforms several validation checks on the block header
// which depend on its position within the block chain.
func (chain *Blockchain) checkBlockHeaderContext(header *wire.BlockHeader, prevNode *BlockNode, flags BehaviorFlags) error {
	// The genesis block is valid by definition.
	if prevNode == nil {
		return nil
	}

	// pk has been banned
	isBanned, err := chain.dmd.isPubKeyBanned(prevNode, header.PublicKey())
	if err != nil {
		return err
	}
	if isBanned {
		logging.CPrint(logging.ERROR, "block builder pubkey has been banned",
			logging.LogFormat{"pubkey": hex.EncodeToString(header.PublicKey().SerializeCompressed())})

		return ErrBannedPk
	}

	// Ensure Target
	expectedTarget, err := calcNextTarget(prevNode, header.Timestamp, chain.chainParams)
	if err != nil {
		return err
	}
	blockDifficulty := header.Target
	if blockDifficulty.Cmp(expectedTarget) != 0 {
		logging.CPrint(logging.ERROR, "block difficulty is not the expected value",
			logging.LogFormat{"difficulty": blockDifficulty, "expectedTarget": expectedTarget})
		return ErrUnexpectedDifficulty
	}

	blockHeight := prevNode.Height + 1
	// Ensure the header BlockHeight matches height calculated in BlockNode.
	if blockHeight != header.Height {
		logging.CPrint(logging.ERROR, "block height does not match the expected height",
			logging.LogFormat{"block Height": header.Height, "expected Height": blockHeight})
		return ErrBadBlockHeight
	}

	// Ensure chain matches up to predetermined checkpoints.
	blockHash := header.BlockHash()
	if !chain.verifyCheckpoint(blockHeight, &blockHash) {
		return fmt.Errorf("%s: block at height %d does not match checkpoint hash", ErrBadCheckpoint, blockHeight)
	}

	// Find the previous checkpoint and prevent blocks which fork the main
	// chain before it.  This prevents storage of new, otherwise valid,
	// blocks which build off of old blocks that are likely at a much easier
	// difficulty and therefore could be used to waste cache and disk space.
	checkpointNode, err := chain.findPreviousCheckpoint()
	if err != nil {
		return err
	}
	if checkpointNode != nil && blockHeight < checkpointNode.Height {
		return fmt.Errorf("%s: block at height %d forks the main chain before the previous checkpoint at height %d",
			ErrForkTooOld, blockHeight, checkpointNode.Height)
	}

	// Ensure the provided challenge in header is right.
	// The calculated challenge based on some rules.
	challenge, err := calcNextChallenge(prevNode)
	if err != nil {
		return err
	}
	if !challenge.IsEqual(&header.Challenge) {
		logging.CPrint(logging.ERROR, "block challenge does not match the expected challenge",
			logging.LogFormat{"block challenge": header.Challenge, "blockHeight": blockHeight, "expectedChallenge": challenge})
		return ErrUnexpectedChallenge
	}

	// Ensure the timestamp for the block header is after its
	// preNode's header timestamp
	if header.Timestamp.Unix()/poc.PoCSlot <= prevNode.Timestamp.Unix()/poc.PoCSlot {
		logging.CPrint(logging.ERROR, "block timestamp is not after expected prevNode",
			logging.LogFormat{"header timestamp": header.Timestamp, "prevNode timestamp": prevNode.Timestamp})
		return ErrTimeTooOld
	}

	return nil
}

// checkBlockContext peforms several validation checks on the block which depend
// on its position within the block chain.
//
// The flags modify the behavior of this function as follows:
//  - BFFastAdd: The transaction are not checked to see if they are finalized
//    and the somewhat expensive BIP0034 validation is not performed.
//
// The flags are also passed to checkBlockHeaderContext.  See its documentation
// for how the flags modify its behavior.
func (chain *Blockchain) checkBlockContext(block *massutil.Block, prevNode *BlockNode, flags BehaviorFlags) error {
	// The genesis block is valid by definition.
	if prevNode == nil {
		return nil
	}

	// Perform all block header related validation checks.
	header := &block.MsgBlock().Header

	if !flags.isFlagSet(BFNoPoCCheck) {
		err := chain.checkBlockHeaderContext(header, prevNode, flags)
		if err != nil {
			return err
		}
	}

	err := chain.checkProposalContext(header.BannedPublicKeys(), prevNode)
	if err != nil {
		return err
	}

	blockTime, err := chain.calcPastMedianTime(prevNode)
	if err != nil {
		return err
	}

	// Ensure all transactions in the block are finalized.
	for _, tx := range block.Transactions() {
		if !IsFinalizedTransaction(tx, block.Height(), blockTime) {
			logging.CPrint(logging.ERROR, "block contains unfinalized transaction", logging.LogFormat{"tx": tx.Hash(), "block": block.Hash()})
			return errUnFinalizedTx
		}
	}

	return nil
}

// CheckCoinbaseHeight checks whether block height in coinbase matches block
// height in header. We do not check *block's existence because this func
// is called in another func that *block exists.
func CheckCoinbaseHeight(block *massutil.Block) error {
	coinbaseTx := block.Transactions()[0]
	blockHeight := block.MsgBlock().Header.Height
	return checkSerializedHeight(coinbaseTx, blockHeight)
}

// extractCoinbaseHeight attempts to extract the height of the block from
// coinbase payload
func extractCoinbaseHeight(coinbaseTx *massutil.Tx) (uint64, error) {
	payload := coinbaseTx.MsgTx().Payload
	if len(payload) < 8 {
		return 0, errIncompleteCoinbasePayload
	}
	return binary.LittleEndian.Uint64(payload[:8]), nil
}

// extractCoinbaseHeight attempts to extract the number of lock reward
// of current block from coinbase payload
func extractCoinbaseStakingRewardNumber(coinbaseTx *massutil.Tx) (uint32, error) {
	payload := coinbaseTx.MsgTx().Payload
	if len(payload) < 12 {
		return 0, errIncompleteCoinbasePayload
	}
	return binary.LittleEndian.Uint32(payload[8:12]), nil
}

// checkSerializedHeight checks if the signature script in the passed
// transaction starts with the serialized block height of wantHeight.
func checkSerializedHeight(coinbaseTx *massutil.Tx, wantHeight uint64) error {
	serializedHeight, err := extractCoinbaseHeight(coinbaseTx)
	if err != nil {
		return err
	}

	if serializedHeight != wantHeight {
		logging.CPrint(logging.ERROR, "the coinbase payload serialized block height does not equal expected height",
			logging.LogFormat{"serializedHeight": serializedHeight, "wantHeight": wantHeight})
		return ErrBadCoinbaseHeight
	}
	return nil
}

// isTransactionSpent returns whether or not the provided transaction data
// describes a fully spent transaction.  A fully spent transaction is one where
// all outputs have been spent.
func isTransactionSpent(txD *TxData) bool {
	for _, isOutputSpent := range txD.Spent {
		if !isOutputSpent {
			return false
		}
	}
	return true
}

// checkDupTx ensures blocks do not contain duplicate transactions which
// 'overwrite' older transactions that are not fully spent.  This prevents an
// attack where a coinbase and all of its dependent transactions could be
// duplicated to effectively revert the overwritten transactions to a single
// confirmation thereby making them vulnerable to a double spend.
func (chain *Blockchain) checkDupTx(node *BlockNode, block *massutil.Block) error {
	// Attempt to fetch duplicate transactions for all of the transactions
	// in this block from the point of view of the Parent node.
	fetchSet := make(map[wire.Hash]struct{})
	for _, tx := range block.Transactions() {
		fetchSet[*tx.Hash()] = struct{}{}
	}
	txResults, err := chain.fetchTxStore(node, fetchSet)
	if err != nil {
		return err
	}

	// Examine the resulting data about the requested transactions.
	for _, txD := range txResults {
		switch txD.Err {
		// A duplicate transaction was not found.  This is the most
		// common case.
		case database.ErrTxShaMissing:
			continue

			// A duplicate transaction was found.  This is only allowed if
			// the duplicate transaction is fully spent.
		case nil:
			if !isTransactionSpent(txD) {
				logging.CPrint(logging.ERROR, "tried to overwrite not fully spent transaction",
					logging.LogFormat{"transaction ": txD.Hash, "block height": txD.BlockHeight})
				return ErrOverwriteTx
			}

			// Some other unexpected error occurred.  Return it now.
		default:
			return txD.Err
		}
	}

	return nil
}

func checkDupSpend(preOutPoint wire.OutPoint, spent []bool) error {
	if preOutPoint.Index >= uint32(len(spent)) {
		logging.CPrint(logging.ERROR, "out of bounds input index in referenced transaction",
			logging.LogFormat{"originTx": preOutPoint.Hash, "input index": preOutPoint.Index, "spent length": len(spent)})
		return ErrBadTxInput
	}
	if spent[preOutPoint.Index] {
		logging.CPrint(logging.ERROR, "transaction tried to double spend output",
			logging.LogFormat{"originTx": preOutPoint.Hash, "input index": preOutPoint.Index})
		return ErrDoubleSpend
	}
	return nil
}

// checkTxInMaturity ensures the transaction is not spending coins which have not
// yet reached the required coinbase maturity.
func checkTxInMaturity(txData *TxData, txHeight uint64, preOutPoint wire.OutPoint, isCoinbase bool) error {
	blocksSincePrev := uint64(0)
	if txHeight > txData.BlockHeight {
		blocksSincePrev = txHeight - txData.BlockHeight
	}
	if IsCoinBase(txData.Tx) {
		if blocksSincePrev < consensus.CoinbaseMaturity {
			logging.CPrint(logging.WARN, "try to spend immature coinbase",
				logging.LogFormat{
					"next block height": txHeight,
					"txIn height":       txData.BlockHeight,
					"coinbase maturity": consensus.CoinbaseMaturity,
					"txInHash":          preOutPoint.Hash,
					"txInIndex":         preOutPoint.Index,
				})
			return ErrImmatureSpend
		}
		return nil
	}
	if isCoinbase {
		if blocksSincePrev < consensus.TransactionMaturity {
			logging.CPrint(logging.ERROR, "try to spend immature transaction",
				logging.LogFormat{
					"next block height":     txHeight,
					"txIn height":           txData.BlockHeight,
					"transactions maturity": consensus.TransactionMaturity,
					"txInHash":              preOutPoint.Hash,
					"txInIndex":             preOutPoint.Index,
				})
			return ErrImmatureSpend
		}
	}
	return nil
}

// CheckTransactionInputs performs a series of checks on the inputs to a
// transaction to ensure they are valid.  An example of some of the checks
// include verifying all inputs exist, ensuring the coinbase seasoning
// requirements are met, detecting double spends, validating all values and fees
// are in the legal range and the total output amount doesn't exceed the input
// amount, and verifying the signatures to prove the spender was the owner of
// the masses and therefore allowed to spend them.  As it checks the inputs,
// it also calculates the total fees for the transaction and returns that value.
func CheckTransactionInputs(tx *massutil.Tx, txHeight uint64, txStore TxStore) (massutil.Amount, error) {
	// Coinbase transactions have no inputs.
	if IsCoinBase(tx) {
		for i, txIn := range tx.MsgTx().TxIn {
			if txIn.Witness.PlainSize() != 0 {
				logging.CPrint(logging.ERROR, "coinbaseTx txIn`s witness size must be 0",
					logging.LogFormat{"index ": i, "size": txIn.Witness.PlainSize()})
				return massutil.ZeroAmount(), ErrCoinbaseTxInWitness
			}
		}
		return massutil.ZeroAmount(), nil
	}
	txHash := tx.Hash()
	totalMaxwellIn := massutil.ZeroAmount()
	for _, txIn := range tx.MsgTx().TxIn {
		// Ensure the input is available.
		txInHash := &txIn.PreviousOutPoint.Hash
		originTxIndex := txIn.PreviousOutPoint.Index
		originTx, exists := txStore[*txInHash]
		if !exists || originTx.Err != nil || originTx.Tx == nil {
			logging.CPrint(logging.ERROR, "unable to find input transaction",
				logging.LogFormat{"input transaction ": txInHash, "transaction": txHash})
			return massutil.ZeroAmount(), ErrMissingTx
		}

		// Ensure the transaction is not spending coins which have not
		// yet reached the required coinbase maturity.
		err := checkTxInMaturity(originTx, txHeight, txIn.PreviousOutPoint, false)
		if err != nil {
			return massutil.ZeroAmount(), err
		}

		// Ensure the transaction is not double spending coins.
		err = checkDupSpend(txIn.PreviousOutPoint, originTx.Spent)
		if err != nil {
			return massutil.ZeroAmount(), err
		}

		// Ensure the transaction amounts are in range.  Each of the
		// output values of the input transactions must not be negative
		// or more than the max allowed per transaction.  All amounts in
		// a transaction are in a unit value known as a maxwell.  One
		// mass is a quantity of maxwell as defined by the
		// MaxwellPerMass constant.
		originTxMaxwell, err := massutil.NewAmountFromInt(originTx.Tx.MsgTx().TxOut[originTxIndex].Value)
		if err != nil {
			logging.CPrint(logging.ERROR, "invalid input value",
				logging.LogFormat{
					"prevTx":    txInHash.String(),
					"prevIndex": originTxIndex,
					"value":     originTx.Tx.MsgTx().TxOut[originTxIndex].Value,
					"err":       err,
				})
			return massutil.ZeroAmount(), err
		}

		totalMaxwellIn, err = totalMaxwellIn.Add(originTxMaxwell)
		if err != nil {
			logging.CPrint(logging.ERROR, "calc total input value error",
				logging.LogFormat{
					"tx":     tx.MsgTx().TxHash().String(),
					"height": txHeight,
					"err":    err,
				})
			return massutil.ZeroAmount(), err
		}

		// Mark the referenced output as spent.
		originTx.Spent[originTxIndex] = true
	}

	// Calculate the total output amount for this transaction.  It is safe
	// to ignore overflow and out of range errors here because those error
	// conditions would have already been caught by checkTransactionSanity.
	totalMaxwellOut := massutil.ZeroAmount()
	for _, txOut := range tx.MsgTx().TxOut {

		v, err := massutil.NewAmountFromInt(txOut.Value)
		if err != nil {
			logging.CPrint(logging.ERROR, "invalid output value",
				logging.LogFormat{
					"tx":     tx.MsgTx().TxHash().String(),
					"height": txHeight,
					"value":  txOut.Value,
					"err":    err,
				})
			return massutil.ZeroAmount(), err
		}

		totalMaxwellOut, err = totalMaxwellOut.Add(v)
		if err != nil {
			logging.CPrint(logging.ERROR, "calc total output value error",
				logging.LogFormat{
					"tx":     tx.MsgTx().TxHash().String(),
					"height": txHeight,
					"err":    err,
				})
			return massutil.ZeroAmount(), err
		}
	}

	return totalMaxwellIn.Sub(totalMaxwellOut)
}

func (chain *Blockchain) checkConnectBlock(node *BlockNode, block *massutil.Block, flags BehaviorFlags, reorgBindingState state.Trie) error {
	// The coinbase for the Genesis block is not spendable, so just return
	// an error now.
	if node.Hash.IsEqual(chain.chainParams.GenesisHash) {
		return ErrConnectGenesis
	}

	// Have to prevent blocks which contain duplicate
	// transactions that 'overwrite' older transactions which are not fully
	// spent. Check this in checkDupTx.
	err := chain.checkDupTx(node, block)
	if err != nil {
		return err
	}

	// Request a map that contains all input transactions for the block from
	// the point of view of its position within the block chain.  These
	// transactions are needed for verification of things such as
	// transaction inputs, counting pay-to-script-hashes, and scripts.
	txInputStore, err := chain.fetchInputTransactions(node, block)
	if err != nil {
		return err
	}

	// The number of signature operations must be less than the maximum
	// allowed per block.  Note that the preliminary sanity checks on a
	// block also include a check similar to this one, but this check
	// expands the count to include a precise count of pay-to-script-hash
	// signature operations in each of the input transaction public key
	// scripts.
	transactions := block.Transactions()
	totalSigOps := 0

	for _, tx := range transactions {
		// Since the first (and only the first) transaction has
		// already been verified to be a coinbase transaction,
		// use i == 0 as an optimization for the flag to
		// countP2SHSigOps for whether or not the transaction is
		// a coinbase transaction rather than having to do a
		// full coinbase check again.
		numsigOps := CountSigOps(tx)

		// Check for overflow or going over the limits.  We have to do
		// this on every loop iteration to avoid overflow.
		lastSigops := totalSigOps
		totalSigOps += numsigOps
		if totalSigOps < lastSigops || totalSigOps > MaxSigOpsPerBlock {
			logging.CPrint(logging.ERROR, "block contains too many signature operations",
				logging.LogFormat{"totalSigOps": totalSigOps, "maxSigOps": MaxSigOpsPerBlock})
			return ErrTooManySigOps
		}
	}

	enforceMassIp2WarmUp := forks.EnforceMASSIP0002WarmUp(block.Height())
	// Perform several checks on the inputs for each transaction.  Also
	// accumulate the total fees.  This could technically be combined with
	// the loop above instead of running another loop over the transactions,
	// but by separating it we can avoid running the more expensive (though
	// still relatively cheap as compared to running the scripts) checks
	// against all the inputs when the signature operations are out of
	// bounds.
	totalFees := massutil.ZeroAmount()
	for i, tx := range transactions {
		txFee, err := CheckTransactionInputs(tx, node.Height, txInputStore)
		if err != nil {
			logging.CPrint(logging.ERROR, "check transaction inputs failed", logging.LogFormat{
				"tx":     tx.Hash(),
				"index":  i,
				"height": node.Height,
				"block":  node.Hash,
				"err":    err,
			})
			return err
		}
		if i != 0 && enforceMassIp2WarmUp {
			if payload := DecodePayload(tx.MsgTx().Payload); payload != nil {
				switch payload.Method {
				case BindPoolCoinbase:
					if txFee.IntValue() < int64(consensus.MASSIP0002SetPoolPkCoinbaseFee) {
						return ErrFeeForPoolPkCoinbase
					}
					if payload.Params.(*BindPoolCoinbaseParams).Nonce == 0 {
						logging.CPrint(logging.ERROR, "zero payload nonce not allowed", logging.LogFormat{"tx": tx.Hash()})
						return ErrPayloadNonce
					}
				default:
					// do nothing
				}
			}
		}

		// Sum the total fees and ensure we don't overflow the
		// accumulator.
		totalFees, err = totalFees.Add(txFee)
		if err != nil {
			logging.CPrint(logging.ERROR, "sum fees error", logging.LogFormat{"err": err})
			return ErrBadFees
		}
	}

	if !flags.isFlagSet(BFNoPoCCheck) {
		if err = chain.validateCoinbase(block, node, txInputStore, totalFees, chain.chainParams, reorgBindingState); err != nil {
			logging.CPrint(logging.ERROR, "Failed to validate coinbase",
				logging.LogFormat{
					"height": block.Height(),
					"block":  block.Hash(),
					"err":    err,
				})
			return err
		}
	}

	// no any flags
	var scriptFlags txscript.ScriptFlags

	// We obtain the MTP of the *previous* block in order to
	// determine if transactions in the current block are final.
	medianTime, err := chain.CalcPastMedianTime()
	if err != nil {
		return err
	}

	// Additionally, if the CSV soft-fork package is now active,
	// then we also enforce the relative sequence number based
	// lock-times within the inputs of all transactions in this
	// candidate block.
	for _, tx := range block.Transactions() {
		// A transaction can only be included within a block
		// once the sequence locks of *all* its inputs are
		// active.
		sequenceLock, err := chain.calcSequenceLock(node, tx, txInputStore)
		if err != nil {
			return err
		}
		if !SequenceLockActive(sequenceLock, node.Height, medianTime) {
			return ErrSequenceNotSatisfied
		}
		// err = checkParsePkScript(tx, txInputStore)
		// if err != nil {
		// 	logging.CPrint(logging.ERROR, "checkParsePkScript error", logging.LogFormat{"tx": tx.Hash(), "err": err})
		// 	return err
		// }
	}

	bst := reorgBindingState
	if bst == nil { // TODO: maybe use flags is better
		bst, err = node.ParentBindingState(chain.stateBindingDb)
		if err != nil {
			return err
		}
	}
	if err := checkParsePkScriptNew(block.Height(), bst, nil, txInputStore, block.Transactions()...); err != nil {
		logging.CPrint(logging.ERROR, "checkParsePkScript error", logging.LogFormat{"err": err})
		return err
	}

	// Don't run scripts if this node is before the latest known good
	// checkpoint since the validity is verified via the checkpoints (all
	// transactions are included in the merkle root hash and any changes
	// will therefore be detected by the next checkpoint).  This is a huge
	// optimization because running the scripts is the most time consuming
	// portion of block handling.
	runScripts := true
	checkpoint := chain.LatestCheckpoint()
	if (checkpoint != nil && node.Height <= checkpoint.Height) || block.IsFastImport() {
		runScripts = false
	}

	// Now that the inexpensive checks are done and have passed, verify the
	// transactions are actually allowed to spend the coins by running the
	// expensive ECDSA signature check scripts.  Doing this last helps
	// prevent CPU exhaustion attacks.
	if runScripts {
		err := checkBlockScripts(block, txInputStore, scriptFlags, chain.sigCache, chain.hashCache)
		if err != nil {
			return err
		}
	}

	return nil
}

func checkFaultPkSanity(fpk *wire.FaultPubKey, chainID wire.Hash) error {
	if err := fpk.IsValid(); err != nil {
		logging.CPrint(logging.ERROR, "invalid faultPk (checkFaultPkSanity)",
			logging.LogFormat{"err": err})
		return ErrCheckBannedPk
	}
	err0 := checkBlockHeaderSanity(fpk.Testimony[0], chainID, big.NewInt(0), BFNone)
	err1 := checkBlockHeaderSanity(fpk.Testimony[1], chainID, big.NewInt(0), BFNone)
	if err0 != nil || err1 != nil {
		logging.CPrint(logging.ERROR, "invalid faultPk (checkFaultPkSanity, get bad testimony)", logging.LogFormat{"err0": err0, "err1": err1})
		return ErrCheckBannedPk
	}
	return nil
}

func checkBlockProposalSanity(pa *wire.ProposalArea, header *wire.BlockHeader, chainID wire.Hash) error {

	bannedKeys := header.BannedPublicKeys()
	if pa.PunishmentCount() != len(bannedKeys) {
		logging.CPrint(logging.ERROR, "banList count is not equal between header and proposalArea")
		return ErrBanList
	}

	// Do not need to check duplicate banned PubKey, because header has checked this item.
	for i, fpk := range pa.PunishmentArea {
		pk := fpk.PubKey
		if !bytes.Equal(pk.SerializeCompressed(), bannedKeys[i].SerializeCompressed()) {
			logging.CPrint(logging.ERROR, "banList disMatch between header and proposalArea")
			return ErrBanList
		}
	}

	for index, fpk := range pa.PunishmentArea {
		if fpk.Testimony[0].Height > header.Height {
			logging.CPrint(logging.ERROR, "banList contains invalid testimony (higher height on index)",
				logging.LogFormat{"index": index})
			return ErrBanList
		}
		if err := checkFaultPkSanity(fpk, chainID); err != nil {
			logging.CPrint(logging.ERROR, "banList contains invalid testimony (sanity check fail on index)",
				logging.LogFormat{"index": index, "err": err.Error()})
			return ErrBanList
		}
	}

	return nil
}

func (chain *Blockchain) checkProposalContext(banList []interfaces.PublicKey, prevNode *BlockNode) error {
	for _, pk := range banList {
		banned, err := chain.dmd.isPubKeyBanned(prevNode, pk)
		if banned {
			logging.CPrint(logging.ERROR, "pubKey already banned")
			return ErrCheckBannedPk
		}
		if err != nil {
			return err
		}
	}
	return nil
}
