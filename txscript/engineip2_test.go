package txscript_test

import (
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

var hashTypes = []txscript.SigHashType{
	txscript.SigHashAll,
	txscript.SigHashNone,
	txscript.SigHashSingle,
	txscript.SigHashAll | txscript.SigHashAnyOneCanPay,
	txscript.SigHashNone | txscript.SigHashAnyOneCanPay,
	txscript.SigHashSingle | txscript.SigHashAnyOneCanPay,
}

func TestExecuteBindingMASSip2(t *testing.T) {
	w := txscript.NewMockWallet()
	pocPkHash := []byte{
		12, 13, 14, 15, 116,
		12, 13, 14, 15, 116,
		12, 13, 14, 15, 116,
		12, 13, 14, 15, 116,
	}

	pkScript, err := w.BuildBindingPkScript(1, 1, pocPkHash)
	assert.NoError(t, err)

	getScript := txscript.ScriptClosure(func(addr massutil.Address) ([]byte, error) {
		return w.FindRedeemScript(addr), nil
	})

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

	bindingLockedPeriod := consensus.MASSIP0002BindingLockedPeriod

	tests := []struct {
		name          string
		sequence      uint64
		enableMASSip2 bool
		execErr       error
	}{
		{"disable massip2, -1", bindingLockedPeriod - 1, false, nil},
		{"disable massip2, 0", bindingLockedPeriod, false, nil},
		{"disable massip2, +1", bindingLockedPeriod + 1, false, nil},

		{"enable massip2, -1", bindingLockedPeriod - 1, true, fmt.Errorf("[CSV] locktime requirement not satisfied -- locktime is greater than the transaction locktime: %d > %d", bindingLockedPeriod, bindingLockedPeriod-1)},
		{"enable massip2, 0", bindingLockedPeriod, true, nil},
		{"enable massip2, +1", bindingLockedPeriod + 1, true, nil},
	}

	for _, tt := range tests {
		tx := &wire.MsgTx{
			Version: 1,
			TxIn: []*wire.TxIn{
				{
					PreviousOutPoint: wire.OutPoint{Hash: wire.Hash{}, Index: 0},
					Sequence:         tt.sequence,
				},
			},
			TxOut: []*wire.TxOut{
				{Value: 1},
			},
		}

		hashCache := txscript.NewTxSigHashes(tx)
		inputValue := 3000000000
		witness, err := txscript.SignTxOutputWit(&config.ChainParams, tx, 0, int64(inputValue), pkScript, hashCache, txscript.SigHashAll, getSign, getScript)
		assert.NoError(t, err)
		tx.TxIn[0].Witness = witness

		flags := txscript.StandardVerifyFlags
		if tt.enableMASSip2 {
			flags |= txscript.ScriptMASSip2
		}
		t.Run(tt.name, func(t *testing.T) {
			vm, err := txscript.NewEngine(pkScript, tx, 0, flags, nil, hashCache, int64(inputValue))
			assert.NoError(t, err)
			assert.Equal(t, tt.execErr, vm.Execute())
		})
	}
}

func TestIsMASSWitnessProgram(t *testing.T) {
	script := []byte{245, 0, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 2, 3, 4, 0, 32} // 18W8DkbtU6i8advRSkUaSocZqkE2JnDDZEbGH
	addr, err := massutil.NewAddressBindingTarget(script, &config.ChainParams)
	assert.Nil(t, err)
	fmt.Println(addr.EncodeAddress())

	address, err := massutil.DecodeAddress("18W8DkbtU6i8advRSkUaSocZqkE2JnDDZEbGH", &config.ChainParams)
	assert.Nil(t, err)
	bt := address.(*massutil.AddressBindingTarget)
	fmt.Println(bt.ScriptAddress())
	assert.Equal(t, 22, len(bt.ScriptAddress()))
	assert.True(t, bt.EncodeAddress() == "18W8DkbtU6i8advRSkUaSocZqkE2JnDDZEbGH")

	wit, err := massutil.DecodeAddress("ms1qp75qqxpq9qcrssqgzqvzq2ps8pqqqyqcyq5rqwzqpqgpsgpgxp58qp9x4py", &config.ChainParams)
	assert.Nil(t, err)

	// new binding
	scriptNew, err := txscript.PayToBindingScriptHashScript(wit.ScriptAddress(), addr.ScriptAddress())
	assert.Nil(t, err)
	assert.True(t, txscript.IsMASSWitnessProgram(scriptNew))

	// old binding
	pkHash := []byte{245, 0, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 2, 3, 4} // 1PLSZpPDFQCyBCp5ftxVDFBsaoz16h2fJZ
	addr2, err := massutil.NewAddressPubKeyHash(pkHash, &config.ChainParams)
	assert.Nil(t, err)
	scriptOld, err := txscript.PayToBindingScriptHashScript(wit.ScriptAddress(), addr2.ScriptAddress())
	assert.Nil(t, err)
	assert.True(t, txscript.IsMASSWitnessProgram(scriptOld))
	fmt.Println(addr2.ScriptAddress())

	// staking
	stakingAddr, err := massutil.NewAddressStakingScriptHash(wit.ScriptAddress(), &config.ChainParams)
	assert.Nil(t, err)
	stakingScript, err := txscript.PayToStakingAddrScript(stakingAddr, 61440)
	assert.Nil(t, err)
	assert.True(t, txscript.IsMASSWitnessProgram(stakingScript))
}
