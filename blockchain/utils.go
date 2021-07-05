package blockchain

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/massnetorg/mass-core/blockchain/state"
	"github.com/massnetorg/mass-core/consensus"
	"github.com/massnetorg/mass-core/database"
	"github.com/massnetorg/mass-core/database/storage"
	"github.com/massnetorg/mass-core/interfaces"
	"github.com/massnetorg/mass-core/logging"
	"github.com/massnetorg/mass-core/massutil"
	"github.com/massnetorg/mass-core/massutil/safetype"
	"github.com/massnetorg/mass-core/poc/chiapos"
	"github.com/massnetorg/mass-core/pocec"
	"github.com/massnetorg/mass-core/trie/common"
	"github.com/massnetorg/mass-core/txscript"
)

var (
	keyNetworkBinding       = []byte("networkbinding")
	keyPoolPkCoinbasePrefix = []byte("p_")
)

//Verify Signature
func VerifyBytes(data []byte, sig *pocec.Signature, pubkey *pocec.PublicKey) (bool, error) {
	if data == nil {
		err := errors.New("input []byte is nil")
		logging.CPrint(logging.ERROR, "input []byte is nil",
			logging.LogFormat{
				"err": err,
			})
		return false, err
	}
	//verify nil pointer,avoid panic error
	if pubkey == nil || sig == nil {
		logging.CPrint(logging.ERROR, "input pointer is nil",
			logging.LogFormat{
				"err": errors.New("input pointer is nil"),
			})
		return false, errors.New("input pointer is nil")
	}

	//get datahash 32bytes
	dataHash := massutil.Sha256(data)

	return sig.Verify(dataHash, pubkey), nil
}

func EqualPublicKeys(a, b interfaces.PublicKey) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	pkA, ok1 := a.(*pocec.PublicKey)
	pkB, ok2 := b.(*chiapos.G1Element)
	switch {
	case ok1 == ok2:
		return false
	case ok1:
		return pkA.IsEqual(b.(*pocec.PublicKey))
	default:
		return pkB.Equals(a.(*chiapos.G1Element))
	}
}

// Returns nil if not a binding script
func TryParserBindingPK(pkScript []byte) ([]byte, error) {
	class, pops := txscript.GetScriptInfo(pkScript)
	if class == txscript.BindingScriptHashTy {
		_, bindingScriptHash, err := txscript.GetParsedBindingOpcode(pops)
		return bindingScriptHash, err
	}
	return nil, nil
}

func IsDBNotFound(err error) bool {
	return err == storage.ErrNotFound || err == database.ErrBlockShaMissing || err == database.ErrTxShaMissing
}

func GetNetworkBinding(bindingState state.Trie) (massutil.Amount, error) {
	totalBinding := massutil.ZeroAmount()
	oldVal, err := bindingState.TryGet(keyNetworkBinding)
	if err != nil {
		return massutil.ZeroAmount(), err
	}
	if oldVal != nil {
		if uv, err := safetype.NewUint128FromBytes(oldVal); err != nil {
			return massutil.ZeroAmount(), err
		} else if totalBinding, err = massutil.NewAmount(uv); err != nil {
			return massutil.ZeroAmount(), err
		}
	}
	return totalBinding, nil
}

func PutNetworkBinding(bindingState state.Trie, totalBinding massutil.Amount) error {
	bytes := totalBinding.Value().Bytes()
	return bindingState.TryUpdate(keyNetworkBinding, bytes[:])
}

func makePoolPkKey(poolPk []byte) []byte {
	key := make([]byte, 0, len(keyPoolPkCoinbasePrefix)+len(poolPk))
	key = append(key, keyPoolPkCoinbasePrefix...)
	key = append(key, poolPk...)
	return key
}

func CheckNonceAndSetPoolPkCoinbase(trie state.Trie, payload []byte) error {
	if decodedPayload := DecodePayload(payload); decodedPayload != nil {
		switch decodedPayload.Method {
		case BindPoolCoinbase:
			params := decodedPayload.Params.(*BindPoolCoinbaseParams)

			key := makePoolPkKey(params.PoolPK.Bytes())

			// get old value
			oldVal, err := trie.TryGet(key)
			if err != nil {
				logging.CPrint(logging.ERROR, "get coinbase from state failed", logging.LogFormat{"err": err})
				return err
			}
			if oldVal != nil {
				oldNonce := binary.BigEndian.Uint32(oldVal[0:4])
				if params.Nonce <= oldNonce || params.Nonce > oldNonce+uint32(consensus.MASSIP0002PayloadNonceGap) {
					logging.CPrint(logging.WARN, "ignore invalid pool_pk nonce", logging.LogFormat{
						"stateNonce":   oldNonce,
						"payloadNonce": params.Nonce,
					})
					return nil
				}
			} else if params.Nonce == 0 {
				// Actually already checked in checkConnectBlock
				return fmt.Errorf("zero pool_pk nonce not allowed")
			}

			value := make([]byte, 4+len(params.CoinbaseScriptAddress))
			binary.BigEndian.PutUint32(value[0:4], params.Nonce)
			copy(value[4:], params.CoinbaseScriptAddress)
			return trie.TryUpdate(key, value)
		default:
			// do nothing
		}
	}
	return nil
}

func GetPoolPkCoinbase(trie state.Trie, poolPk []byte) ([]byte, uint32, error) {
	key := makePoolPkKey(poolPk)
	value, err := trie.TryGet(key)
	if err != nil || value == nil {
		return nil, 0, err
	}
	if len(value) == 4 {
		return nil, binary.BigEndian.Uint32(value[0:4]), nil
	}
	return value[4:], binary.BigEndian.Uint32(value[0:4]), nil
}

func GetBindingState(bc *Blockchain, root common.Hash) (state.Trie, error) {
	return bc.stateBindingDb.OpenBindingTrie(root)
}
