// Copyright (c) 2013-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
//
package txscript_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/massnetorg/mass-core/config"
	"github.com/massnetorg/mass-core/consensus"
	"github.com/massnetorg/mass-core/massutil"
	"github.com/massnetorg/mass-core/txscript"
	"github.com/massnetorg/mass-core/wire"
	"github.com/stretchr/testify/assert"
)

type addressDetail struct {
	PubKey *btcec.PublicKey
}

func checkScripts(msg string, tx *wire.MsgTx, idx int, witness wire.TxWitness, pkScript []byte, value int64) error {
	tx.TxIn[idx].Witness = witness
	vm, err := txscript.NewEngine(pkScript, tx, idx,
		txscript.StandardVerifyFlags, nil, nil, value)
	if err != nil {
		return fmt.Errorf("failed to make script engine for %s: %v",
			msg, err)
	}

	err = vm.Execute()
	if err != nil {
		return fmt.Errorf("invalid script signature for %s: %v", msg,
			err)
	}

	return nil
}

//sign and execute the script
func signAndCheck(msg string, tx *wire.MsgTx, idx int, pkScript []byte,
	hashType txscript.SigHashType, kdb txscript.GetSignDB, sdb txscript.ScriptDB,
	previousScript []byte, value int64) error {
	hashCache := txscript.NewTxSigHashes(tx)

	witness, err := txscript.SignTxOutputWit(&config.ChainParams, tx,
		idx, value, pkScript, hashCache, hashType, kdb, sdb)
	if err != nil {
		return fmt.Errorf("failed to sign output %s: %v", msg, err)
	}
	tx.TxIn[idx].Witness = witness

	return checkScripts(msg, tx, idx, witness, pkScript, value)
}

func TestAnyoneCanPay(t *testing.T) {
	wit0, _ := txscript.NewScriptBuilder().AddOp(txscript.OP_0).AddOp(txscript.OP_DROP).Script()
	wit1, _ := txscript.NewScriptBuilder().AddOp(txscript.OP_TRUE).Script()
	scriptHash := sha256.Sum256(wit1)
	pkscript, err := txscript.PayToWitnessScriptHashScript(scriptHash[:])
	if err != nil {
		t.FailNow()
	}
	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  wire.Hash{},
					Index: 0,
				},
				Witness:  wire.TxWitness{wit0, wit1},
				Sequence: wire.MaxTxInSequenceNum,
			},
		},
		TxOut: []*wire.TxOut{
			{
				Value: 1,
			},
			{
				Value: 2,
			},
			{
				Value: 3,
			},
		},
		LockTime: 0,
	}

	hashCache := txscript.NewTxSigHashes(tx)
	vm, err := txscript.NewEngine(pkscript, tx, 0, txscript.StandardVerifyFlags, nil, hashCache, 3000000000)
	assert.Nil(t, err)
	if err == nil {
		err = vm.Execute()
		assert.Nil(t, err)
	}
}

//test the signTxOutputWit function
func TestSignTxOutputWit(t *testing.T) {
	// t.Parallel()
	w := txscript.NewMockWallet()
	pkScript, err := w.BuildP2WSHScript(1, 1)
	// find redeem script
	getScript := txscript.ScriptClosure(func(addr massutil.Address) ([]byte, error) {
		// If keys were provided then we can only use the
		// redeem scripts provided with our inputs, too.

		return w.FindRedeemScript(addr), nil
	})
	// find private key
	getSign := txscript.SignClosure(func(pub *btcec.PublicKey, hash []byte) (*btcec.Signature, error) {
		if len(hash) != 32 {
			return nil, errors.New("invalid data to sign")
		}
		privK := w.GetPrivKey(pub)
		if privK == nil {
			return nil, errors.New("private key not found")
		}
		return privK.Sign(hash)
	})
	if err != nil {
		t.Errorf("create wallet error : %v", err)
	}
	// make key
	// make script based on key.
	// sign with magic pixie dust.
	hashTypes := []txscript.SigHashType{
		txscript.SigHashAll,
		txscript.SigHashNone,
		txscript.SigHashSingle,
		txscript.SigHashAll | txscript.SigHashAnyOneCanPay,
		txscript.SigHashNone | txscript.SigHashAnyOneCanPay,
		txscript.SigHashSingle | txscript.SigHashAnyOneCanPay,
	}
	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  wire.Hash{},
					Index: 0,
				},
				Sequence: wire.MaxTxInSequenceNum,
			},
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  wire.Hash{},
					Index: 1,
				},
				Sequence: wire.MaxTxInSequenceNum,
			},
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  wire.Hash{},
					Index: 2,
				},
				Sequence: wire.MaxTxInSequenceNum,
			},
		},
		TxOut: []*wire.TxOut{
			{
				Value: 1,
			},
			{
				Value: 2,
			},
			{
				Value: 3,
			},
		},
		LockTime: 0,
	}

	// p2wsh
	for _, hashType := range hashTypes {
		for i := range tx.TxIn {
			msg := fmt.Sprintf("%d:%d", hashType, i)
			//output value is 0
			var value = 3000000000
			if err := signAndCheck(msg, tx, i, pkScript, hashType,
				getSign, getScript, nil, int64(value)); err != nil {
				t.Error(err)
				break
			}
		}
		bs, err := tx.Bytes(wire.Packet)
		assert.Nil(t, err)
		fmt.Println(pkScript)
		fmt.Println(hex.EncodeToString(bs))
	}
}

//test the signTxOutputWit function
func TestSignStakingTxOutputWit(t *testing.T) {
	// t.Parallel()
	w := txscript.NewMockWallet()
	pkScript, err := w.BuildStakingPkScript(1, 1, consensus.MinFrozenPeriod)
	// find redeem script
	getScript := txscript.ScriptClosure(func(addr massutil.Address) ([]byte, error) {
		return w.FindRedeemScript(addr), nil
	})
	// find private key
	getSign := txscript.SignClosure(func(pub *btcec.PublicKey, hash []byte) (*btcec.Signature, error) {
		if len(hash) != 32 {
			return nil, errors.New("invalid data to sign")
		}
		privK := w.GetPrivKey(pub)
		if privK == nil {
			return nil, errors.New("private key not found")
		}
		return privK.Sign(hash)
	})
	if err != nil {
		t.Errorf("create wallet error : %v", err)
	}
	// make key
	// make script based on key.
	// sign with magic pixie dust.
	hashTypes := []txscript.SigHashType{
		txscript.SigHashAll,
		txscript.SigHashNone,
		txscript.SigHashSingle,
		txscript.SigHashAll | txscript.SigHashAnyOneCanPay,
		txscript.SigHashNone | txscript.SigHashAnyOneCanPay,
		txscript.SigHashSingle | txscript.SigHashAnyOneCanPay,
	}
	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  wire.Hash{},
					Index: 0,
				},
				Sequence: consensus.MinFrozenPeriod + 1,
			},
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  wire.Hash{},
					Index: 1,
				},
				Sequence: consensus.MinFrozenPeriod + 1,
			},
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  wire.Hash{},
					Index: 2,
				},
				Sequence: consensus.MinFrozenPeriod + 1,
			},
		},
		TxOut: []*wire.TxOut{
			{
				Value: 1,
			},
			{
				Value: 2,
			},
			{
				Value: 3,
			},
		},
		LockTime: 0,
	}

	// p2wsh
	for _, hashType := range hashTypes {
		for i := range tx.TxIn {
			msg := fmt.Sprintf("%d:%d", hashType, i)
			//output value is 0
			var value = 0
			if err := signAndCheck(msg, tx, i, pkScript, hashType,
				getSign, getScript, nil, int64(value)); err != nil {
				t.Error(err)
				break
			}
		}
	}
}

//test the signTxOutputWit function
func TestSignBindingTxOutputWit(t *testing.T) {
	// t.Parallel()
	w := txscript.NewMockWallet()

	pocPkHash := []byte{
		12, 13, 14, 15, 116,
		12, 13, 14, 15, 116,
		12, 13, 14, 15, 116,
		12, 13, 14, 15, 116,
	}

	pkScript, err := w.BuildBindingPkScript(1, 1, pocPkHash)
	// find redeem script
	getScript := txscript.ScriptClosure(func(addr massutil.Address) ([]byte, error) {
		return w.FindRedeemScript(addr), nil
	})
	// find private key
	getSign := txscript.SignClosure(func(pub *btcec.PublicKey, hash []byte) (*btcec.Signature, error) {
		if len(hash) != 32 {
			return nil, errors.New("invalid data to sign")
		}
		privK := w.GetPrivKey(pub)
		if privK == nil {
			return nil, errors.New("private key not found")
		}
		return privK.Sign(hash)
	})
	if err != nil {
		t.Errorf("create wallet error : %v", err)
	}
	// make key
	// make script based on key.
	// sign with magic pixie dust.
	hashTypes := []txscript.SigHashType{
		txscript.SigHashAll,
		txscript.SigHashNone,
		txscript.SigHashSingle,
		txscript.SigHashAll | txscript.SigHashAnyOneCanPay,
		txscript.SigHashNone | txscript.SigHashAnyOneCanPay,
		txscript.SigHashSingle | txscript.SigHashAnyOneCanPay,
	}
	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  wire.Hash{},
					Index: 0,
				},
				Sequence: wire.MaxTxInSequenceNum,
			},
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  wire.Hash{},
					Index: 1,
				},
				Sequence: wire.MaxTxInSequenceNum,
			},
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  wire.Hash{},
					Index: 2,
				},
				Sequence: wire.MaxTxInSequenceNum,
			},
		},
		TxOut: []*wire.TxOut{
			{
				Value: 1,
			},
			{
				Value: 2,
			},
			{
				Value: 3,
			},
		},
		LockTime: 0,
	}

	// p2wsh
	for _, hashType := range hashTypes {
		for i := range tx.TxIn {
			msg := fmt.Sprintf("%d:%d", hashType, i)
			//output value is 0
			var value = 0
			if err := signAndCheck(msg, tx, i, pkScript, hashType,
				getSign, getScript, nil, int64(value)); err != nil {
				t.Error(err)
				break
			}
		}
	}
}
