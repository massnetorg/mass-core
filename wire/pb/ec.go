package wirepb

import (
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/massnetorg/mass-core/interfaces"
	"github.com/massnetorg/mass-core/poc/chiapos"
	"github.com/massnetorg/mass-core/pocec"
)

const (
	PublicKeyLengthS256    = 33
	PublicKeyLengthBLS     = 48
	SignatureLengthS256Min = pocec.MinSigLen
	SignatureLengthS256Max = 80
	SignatureLengthBLS     = 96
)

// BigIntToProto get proto BigInt from golang big.Int
func BigIntToProto(x *big.Int) *BigInt {
	if x == nil {
		return nil
	}
	pb := new(BigInt)
	pb.Raw = x.Bytes()
	return pb
}

// ProtoToBigInt get golang big.Int from proto BigInt
func ProtoToBigInt(pb *BigInt, bi *big.Int) error {
	if pb == nil {
		return errors.New("nil proto big_int")
	}
	bi.SetBytes(pb.Raw)
	return nil
}

func (m *BigInt) Bytes() []byte {
	buf := make([]byte, len(m.Raw))
	copy(buf, m.Raw)
	return buf
}

// NewEmptyPublicKey returns new empty initialized proto PublicKey
func NewEmptyPublicKey() *PublicKey {
	return &PublicKey{
		Raw: make([]byte, 0),
	}
}

// PublicKeyToProto accespts a pocec/chiapos PublicKey, returns a proto PublicKey
func PublicKeyToProto(pub interfaces.PublicKey) *PublicKey {
	if pub == nil {
		return nil
	}
	pb := NewEmptyPublicKey()
	pb.Raw = pub.SerializeCompressed()
	return pb
}

// ProtoToPublicKey accepts a proto PublicKey and a pocec/chiapos PublicKey,
// fills content into the latter
func ProtoToPublicKey(pb *PublicKey) (interfaces.PublicKey, error) {
	if pb == nil {
		return nil, errors.New("nil proto public_key")
	}
	switch len(pb.Raw) {
	case PublicKeyLengthS256:
		key, err := pocec.ParsePubKey(pb.Raw, pocec.S256())
		if err != nil {
			return nil, err
		}
		return key, nil
	case PublicKeyLengthBLS:
		key, err := chiapos.NewG1ElementFromBytes(pb.Raw)
		if err != nil {
			return nil, err
		}
		return key, nil
	default:
		return nil, errors.New("unknown public_key length")
	}
}

func (m *PublicKey) Bytes() []byte {
	return m.Raw
}

// NewEmptySignature returns new empty initialized proto Signature
func NewEmptySignature() *Signature {
	return &Signature{
		Raw: make([]byte, 0),
	}
}

// SignatureToProto accepts a pocec/chiapos Signature, returns a proto Signature
func SignatureToProto(sig interfaces.Signature) *Signature {
	if sig == nil {
		return nil
	}
	pb := NewEmptySignature()
	pb.Raw = sig.Serialize()
	return pb
}

// ProtoToSignature accepts a proto Signture and a pocec/chiapos Signture,
// fills content into the latter
func ProtoToSignature(pb *Signature) (interfaces.Signature, error) {
	if pb == nil {
		return nil, errors.New("nil proto signature")
	}
	var length = len(pb.Raw)
	if length == SignatureLengthBLS {
		sig, err := chiapos.NewG2ElementFromBytes(pb.Raw)
		if err != nil {
			return nil, err
		}
		return sig, nil
	} else if SignatureLengthS256Min <= length && length <= SignatureLengthS256Max {
		sig, err := pocec.ParseDERSignature(pb.Raw, pocec.S256())
		if err != nil {
			return nil, err
		}
		return sig, nil
	} else {
		return nil, errors.New("unknown signature length")
	}
}

func (m *Signature) Bytes() []byte {
	return m.Raw
}

func (m *Hash) Bytes() []byte {
	var s0, s1, s2, s3 [8]byte
	binary.LittleEndian.PutUint64(s0[:], m.S0)
	binary.LittleEndian.PutUint64(s1[:], m.S1)
	binary.LittleEndian.PutUint64(s2[:], m.S2)
	binary.LittleEndian.PutUint64(s3[:], m.S3)
	return combineBytes(s0[:], s1[:], s2[:], s3[:])
}
