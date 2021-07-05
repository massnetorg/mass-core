package blockchain

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/massnetorg/mass-core/config"
	"github.com/massnetorg/mass-core/logging"
	"github.com/massnetorg/mass-core/massutil"
	"github.com/massnetorg/mass-core/poc/chiapos"
	"github.com/massnetorg/mass-core/wire"
)

/////////////////////////////
//    coinbase payload
/////////////////////////////
type CoinbasePayload struct {
	height           uint64
	numStakingReward uint32
}

func (p *CoinbasePayload) NumStakingReward() uint32 {
	return p.numStakingReward
}

func (p *CoinbasePayload) Bytes() []byte {
	buf := make([]byte, 12)
	binary.LittleEndian.PutUint64(buf[:8], p.height)
	binary.LittleEndian.PutUint32(buf[8:12], p.numStakingReward)
	return buf
}

func (p *CoinbasePayload) SetBytes(data []byte) error {
	if len(data) < 12 {
		return errIncompleteCoinbasePayload
	}
	p.height = binary.LittleEndian.Uint64(data[0:8])
	p.numStakingReward = binary.LittleEndian.Uint32(data[8:12])
	return nil
}

func NewCoinbasePayload() *CoinbasePayload {
	return &CoinbasePayload{
		height:           0,
		numStakingReward: 0,
	}
}

func standardCoinbasePayload(nextBlockHeight uint64, numStakingReward uint32) []byte {
	p := &CoinbasePayload{
		height:           nextBlockHeight,
		numStakingReward: numStakingReward,
	}
	return p.Bytes()
}

/////////////////////////////
//   tx payload
/////////////////////////////

type PayloadParams interface {
	Encode() []byte
	String() string
}

type PayloadMethod uint16

const (
	BindPoolCoinbase PayloadMethod = 1 + iota // for chia
)

type TransactionPayload struct {
	Method PayloadMethod
	Params PayloadParams
}

func (p *TransactionPayload) String() string {
	if p == nil {
		return ""
	}
	method := "Unknown"
	switch p.Method {
	case BindPoolCoinbase:
		method = "BindPoolPKCoinbase"
	default:
		return method
	}
	return fmt.Sprintf("%s[%s]", method, p.Params.String())
}

//   BindPoolCoinbaseParams
type BindPoolCoinbaseParams struct {
	PoolPK                *chiapos.G1Element
	Signature             *chiapos.G2Element
	CoinbaseScriptAddress []byte // address.ScriptAddress()
	Nonce                 uint32 // start at 1, 0 means not bound
}

func (p *BindPoolCoinbaseParams) String() string {
	var coinbase string
	if len(p.CoinbaseScriptAddress) > 0 {
		addr, err := massutil.NewAddressWitnessScriptHash(p.CoinbaseScriptAddress, &config.ChainParams)
		if err != nil {
			coinbase = err.Error()
		} else {
			coinbase = addr.EncodeAddress()
		}
	}
	return fmt.Sprintf("PoolPK: %s, Nonce: %d, Coinbase: %s, Signature: %s", hex.EncodeToString(p.PoolPK.Bytes()),
		p.Nonce, coinbase, hex.EncodeToString(p.Signature.Bytes()))
}

func NewBindPoolCoinbasePayload(ppk *chiapos.G1Element, sig *chiapos.G2Element, coinbase []byte, nonce uint32) *TransactionPayload {
	if nonce == 0 {
		// nonce should start at 1.
		return nil
	}
	return &TransactionPayload{
		Method: BindPoolCoinbase,
		Params: &BindPoolCoinbaseParams{
			PoolPK:                ppk,
			Signature:             sig,
			CoinbaseScriptAddress: coinbase,
			Nonce:                 nonce,
		},
	}
}

// data structure:
//    [0:48]    - public key
//    [48:144]  - signature
//    [144:148] - nonce
//    [148:]    - witness script hash, length zero to delete
func (params *BindPoolCoinbaseParams) Decode(data []byte) (err error) {
	if len(data) < 148 {
		return fmt.Errorf("invalid payload param length %d, expect at least 148", len(data))
	}
	if params.PoolPK, err = chiapos.NewG1ElementFromBytes(data[0:48]); err != nil {
		return err
	}
	if params.Signature, err = chiapos.NewG2ElementFromBytes(data[48:144]); err != nil {
		return err
	}
	params.Nonce = binary.BigEndian.Uint32(data[144:148])
	if params.Nonce == 0 {
		return fmt.Errorf("zero nonce not allowed")
	}
	params.CoinbaseScriptAddress = data[148:]
	return nil
}

func (params *BindPoolCoinbaseParams) Encode() []byte {
	buf := make([]byte, 148+len(params.CoinbaseScriptAddress))
	copy(buf[0:48], params.PoolPK.Bytes())
	copy(buf[48:144], params.Signature.Bytes())
	binary.BigEndian.PutUint32(buf[144:148], params.Nonce)
	copy(buf[148:148+len(params.CoinbaseScriptAddress)], params.CoinbaseScriptAddress)
	return buf
}

func EncodePayload(payload *TransactionPayload) []byte {
	params := payload.Params.Encode()
	buf := make([]byte, 2+len(params))
	binary.BigEndian.PutUint16(buf[0:2], uint16(payload.Method))
	copy(buf[2:], params)
	return buf
}

// DecodePayload return nil if decoding failed or verify sig failed, regarding
// it as meaningless payload.
func DecodePayload(payload []byte) *TransactionPayload {
	if len(payload) < 2 {
		return nil
	}
	method := binary.BigEndian.Uint16(payload[0:2])
	switch method {
	case uint16(BindPoolCoinbase):
		params := &BindPoolCoinbaseParams{}
		if err := params.Decode(payload[2:]); err != nil {
			logging.CPrint(logging.WARN, "decode payload error", logging.LogFormat{
				"method": "BindPoolCoinbase",
				"err":    err,
			})
			return nil
		}
		ok, err := VerifyPoolPkPayload(params.PoolPK, params.Signature, params.CoinbaseScriptAddress, params.Nonce)
		if !ok {
			logging.CPrint(logging.WARN, "verify binding payload sig failed", logging.LogFormat{"err": err})
			return nil
		}
		return &TransactionPayload{
			Method: BindPoolCoinbase,
			Params: params,
		}
	default:
	}
	return nil
}

func VerifyPoolPkPayload(poolPk *chiapos.G1Element, signature *chiapos.G2Element, coinbaseScriptAddress []byte, nonce uint32) (bool, error) {
	if nonce == 0 {
		return false, fmt.Errorf("zero nonce not allowed")
	}
	// Serialize: (PoolPK (48 Bytes) || || Nonce(4 bytes) || Length (4 Bytes) || CoinbaseScriptAddress)
	var nonceBuf [4]byte
	binary.BigEndian.PutUint32(nonceBuf[:], nonce)
	var b4 [4]byte
	binary.LittleEndian.PutUint32(b4[:], uint32(len(coinbaseScriptAddress)))
	content := bytes.Join([][]byte{
		poolPk.Bytes(),
		nonceBuf[:],
		b4[:],
		coinbaseScriptAddress,
	}, nil)
	// Sign: SHA256(content) -> Verify
	hash := wire.HashB(content)
	return chiapos.NewAugSchemeMPL().Verify(poolPk, hash, signature)
}

func SignPoolPkPayload(poolSk *chiapos.PrivateKey, coinbaseScriptAddress []byte, nonce uint32) (*chiapos.G2Element, error) {
	if nonce == 0 {
		return nil, fmt.Errorf("zero nonce not allowed")
	}

	poolPk, err := poolSk.GetG1()
	if err != nil {
		return nil, err
	}

	var nonceBuf [4]byte
	binary.BigEndian.PutUint32(nonceBuf[:], nonce)

	var b4 [4]byte
	binary.LittleEndian.PutUint32(b4[:], uint32(len(coinbaseScriptAddress)))
	content := bytes.Join([][]byte{
		poolPk.Bytes(),
		nonceBuf[:],
		b4[:],
		coinbaseScriptAddress,
	}, nil)
	hash := wire.HashB(content)
	return chiapos.NewAugSchemeMPL().Sign(poolSk, hash)
}
