package blockchain

import (
	"github.com/massnetorg/mass-core/blockchain/state"
	"github.com/massnetorg/mass-core/logging"
	"github.com/massnetorg/mass-core/txscript"
	"github.com/massnetorg/mass-core/wire"
)

//
func indexTxInPkScriptForMassip2(
	bindingState state.Trie,
	txout *wire.TxOut,
	txAddrIndex shTxLoc,
	locInBlock *wire.TxLoc,
) (isBinding bool, err error) {

	var holderScriptHash []byte

	scriptClass, pops := txscript.GetScriptInfo(txout.PkScript)
	switch scriptClass {
	case txscript.WitnessV0ScriptHashTy, txscript.StakingScriptHashTy:
		// TODO: more rigorous inspection
		_, rsh, err := txscript.GetParsedOpcode(pops, scriptClass)
		if err != nil {
			logging.CPrint(logging.ERROR, "failed to parse opcode")
			return false, err
		}
		holderScriptHash = rsh[:]

	case txscript.BindingScriptHashTy:
		var bindingScriptHash []byte
		holderScriptHash, bindingScriptHash, err = txscript.GetParsedBindingOpcode(pops)
		if err != nil {
			logging.CPrint(logging.ERROR, "failed to parse binding opcode", logging.LogFormat{"err": err})
			return false, err
		}
		if len(bindingScriptHash) != txscript.OP_DATA_22 {
			logging.CPrint(logging.ERROR, "unexpected script length", logging.LogFormat{"expect": 22, "actual": len(bindingScriptHash)})
			return false, ErrInvalidBindingScript
		}

		if buf, _ := bindingState.TryGet(bindingScriptHash); buf == nil { // err does no matter.
			return false, ErrPlotPKNotBound
		}
		if err := bindingState.TryDelete(bindingScriptHash); err != nil {
			return false, err
		}
		isBinding = true
	default:
		logging.CPrint(logging.DEBUG, "nonstandard tx")
		return false, nil
	}

	var txKey [txIndexKeyLen]byte
	copy(txKey[:], mustEncodeTxIndexKey(holderScriptHash, locInBlock.TxStart, locInBlock.TxLen))
	if _, ok := txAddrIndex[txKey]; !ok {
		txAddrIndex[txKey] = struct{}{}
	}

	return isBinding, nil
}

func indexTxOutPkScriptForMassip2(
	bindingState state.Trie,
	txout *wire.TxOut,
	txAddrIndex shTxLoc,
	locInBlock *wire.TxLoc,
) (isBinding bool, err error) {

	var holderScriptHash []byte

	scriptClass, pops := txscript.GetScriptInfo(txout.PkScript)
	switch scriptClass {
	case txscript.WitnessV0ScriptHashTy, txscript.StakingScriptHashTy:
		// TODO: more rigorous inspection
		_, rsh, err := txscript.GetParsedOpcode(pops, scriptClass)
		if err != nil {
			logging.CPrint(logging.ERROR, "failed to parse opcode")
			return false, err
		}
		holderScriptHash = rsh[:]

	case txscript.BindingScriptHashTy:
		var bindingScriptHash []byte
		holderScriptHash, bindingScriptHash, err = txscript.GetParsedBindingOpcode(pops)
		if err != nil {
			logging.CPrint(logging.ERROR, "failed to parse binding opcode", logging.LogFormat{"error": err})
			return false, err
		}
		if len(bindingScriptHash) != txscript.OP_DATA_22 {
			return false, ErrInvalidBindingScript
		}

		if buf, err := bindingState.TryGet(bindingScriptHash); err != nil {
			return false, err
		} else if buf != nil {
			return false, ErrPlotPKAlreadyBound
		}

		err = bindingState.TryUpdate(bindingScriptHash, state.EncodeBindingInfo(&state.BindingInfo{
			Amount: txout.Value,
		}))
		if err != nil {
			return false, err
		}
		isBinding = true
	default:
		logging.CPrint(logging.DEBUG, "nonstandard tx")
		return false, nil
	}

	var txKey [txIndexKeyLen]byte
	copy(txKey[:], mustEncodeTxIndexKey(holderScriptHash, locInBlock.TxStart, locInBlock.TxLen))
	if _, ok := txAddrIndex[txKey]; !ok {
		txAddrIndex[txKey] = struct{}{}
	}

	return isBinding, nil
}
