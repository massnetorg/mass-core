package wirepb

import (
	"math/big"
	"math/rand"
	"reflect"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/massnetorg/mass-core/pocec"
	"github.com/stretchr/testify/require"
)

// TestBigInt tests encode/decode BigInt.
func TestBigInt(t *testing.T) {
	x := new(big.Int).SetUint64(uint64(0xffffffffffffffff))
	x = x.Mul(x, x)
	pb := BigIntToProto(x)
	y := new(big.Int)
	if err := ProtoToBigInt(pb, y); err != nil {
		t.Error("proto to big int error", err)
	}
	if !reflect.DeepEqual(x, y) {
		t.Error("obj BigInt not equal")
	}
}

// TestPublicKey test encode/decode PublicKey.
func TestPublicKey(t *testing.T) {
	pocPriv, err := pocec.NewPrivateKey(pocec.S256())
	if err != nil {
		t.Fatal(err)
	}
	pocPub := pocPriv.PubKey()
	pocProto := PublicKeyToProto(pocPub)
	pocPubNew, err := ProtoToPublicKey(pocProto)
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(pocPub, pocPubNew.(*pocec.PublicKey)) {
		t.Error("obj pocec PublicKey not equal")
	}
}

// TestSignature tests encode/decode Signature.
func TestSignature(t *testing.T) {
	btcSig := &btcec.Signature{
		R: new(big.Int).SetUint64(rand.Uint64()),
		S: new(big.Int).SetUint64(rand.Uint64()),
	}
	btcProto := SignatureToProto(btcSig)
	btcSigNew, err := ProtoToSignature(btcProto)
	if err != nil {
		t.Error(err)
	}
	sigNew, ok := btcSigNew.(*pocec.Signature)
	require.True(t, ok && btcSig.R.Cmp(sigNew.R) == 0 && btcSig.S.Cmp(sigNew.S) == 0, "obj btcec Signature not equal")

	pocSig := &pocec.Signature{
		R: new(big.Int).SetUint64(rand.Uint64()),
		S: new(big.Int).SetUint64(rand.Uint64()),
	}
	pocProto := SignatureToProto(pocSig)
	pocSigNew, err := ProtoToSignature(pocProto)
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(pocSig, pocSigNew) {
		t.Error("obj pocec Signature not equal")
	}
}
