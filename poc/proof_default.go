package poc

import (
	"encoding/binary"
	"math/big"

	"github.com/massnetorg/mass-core/poc/chiapos"
	"github.com/massnetorg/mass-core/poc/pocutil"
)

const massProofByteLength = 17

func DefaultPlotSize(bl int) uint64 {
	return uint64(bl * (1 << uint(bl-2)))
	//return uint64(pocutil.RecordSize(bl) * 2 * (1 << uint(bl)))
}

// Proof represents a single PoC Proof.
type DefaultProof struct {
	X      []byte
	XPrime []byte
	BL     int
}

func GetDefaultProof(proof Proof) (*DefaultProof, error) {
	if proof == nil {
		return nil, ErrProofNilItf
	}
	p, ok := proof.(*DefaultProof)
	if !ok {
		return nil, ErrProofType
	}
	return p, nil
}

func MustGetDefaultProof(proof Proof) *DefaultProof {
	return proof.(*DefaultProof)
}

func NewDefaultProof(x, xp []byte, bl int) *DefaultProof {
	return &DefaultProof{
		X:      x,
		XPrime: xp,
		BL:     bl,
	}
}

// Type returns the type of proof
func (proof *DefaultProof) Type() ProofType {
	return ProofTypeDefault
}

func (proof *DefaultProof) BitLength() int {
	return int(proof.BL)
}

// Encode encodes proof to 17 bytes:
// |    X    | XPrime  | BitLength |
// | 8 bytes | 8 bytes |   1 byte  |
// X & XPrime is encoded in little endian
func (proof *DefaultProof) Encode() []byte {
	var data [massProofByteLength]byte
	copy(data[:8], proof.X)
	copy(data[8:16], proof.XPrime)
	data[16] = uint8(proof.BL)

	return data[:]
}

// Decode decodes proof from a 17-byte slice:
// |    X    | XPrime  | BitLength |
// | 8 bytes | 8 bytes |   1 byte  |
// X & XPrime is encoded in little endian
func (proof *DefaultProof) Decode(data []byte) error {
	if len(data) != massProofByteLength {
		return ErrProofDecodeDataSize
	}
	proof.BL = int(data[16])
	proof.X = pocutil.PoCValue2Bytes(pocutil.PoCValue(binary.LittleEndian.Uint64(data[:8])), proof.BL)
	proof.XPrime = pocutil.PoCValue2Bytes(pocutil.PoCValue(binary.LittleEndian.Uint64(data[8:16])), proof.BL)
	return nil
}

// Quality produces the relative quality of a proof.
//
// Here we define:
// (1) H: (a hash value) as an (32-byte-big-endian-encoded) integer ranges in 0 ~ 2^256 - 1.
// (2) SIZE: the volume of record of certain BitLength, which equals to 2^BitLength.
//
// The standard quality is : quality = (H / 2^256) ^ [1 / (SIZE * BitLength)],
// which means the more space you have, the bigger prob you get to
// generate a higher quality.
//
// In MASS we use an equivalent quality formula : Quality = (SIZE * BitLength) / [256 - log2(H)],
// which means the more space you have, the bigger prob you get to
// generate a higher Quality.
//
// A proof is considered as valid when Quality >= target.
func (proof *DefaultProof) Quality(slot, height uint64) *big.Int {
	hashVal := proof.GetHashVal(slot, height)
	q1 := Q1FactorDefault(proof.BL)
	if EnforceMASSIP0002(height) {
		q1.Mul(q1, big.NewFloat(QualityConstantMASSIP0002))
	}
	return GetQuality(q1, hashVal)
}

// verifyProofMASS verifies proof:
// (1) make sure BitLength is Valid. Should be integer even number in [24, 40].
// (2) perform function P on x and x_prime, the corresponding result
//     y and y_prime should be a bit-flip pair.
// (3) perform function F on x and x_prime, the result z should
//     be equal to the bit-length-cut challenge.
// It returns nil when proof is verified.
func (proof *DefaultProof) Verify(pubKeyHash pocutil.Hash, challenge pocutil.Hash, filter bool) error {
	bl := proof.BL
	if !ProofTypeDefault.EnsureBitLength(bl) {
		return ErrProofInvalidBitLength
	}

	if filter && !chiapos.PassPlotFilter(pubKeyHash, challenge) {
		return ErrProofFilter
	}

	y := pocutil.PB(proof.X, bl, pubKeyHash)
	yp := pocutil.PB(proof.XPrime, bl, pubKeyHash)
	if y != pocutil.FlipValue(yp, bl) {
		return ErrProofInvalidFlipValue
	}

	cShort := pocutil.CutHash(challenge, bl)
	z := pocutil.FB(proof.X, proof.XPrime, bl, pubKeyHash)
	if cShort != z {
		return ErrProofInvalidChallenge
	}

	return nil
}

// VerifiedQuality verifies the proof and then calculates its quality.
func (proof *DefaultProof) VerifiedQuality(pubKeyHash pocutil.Hash, challenge pocutil.Hash, filter bool, slot, height uint64) (*big.Int, error) {
	if err := proof.Verify(pubKeyHash, challenge, filter); err != nil {
		return nil, err
	}
	return proof.Quality(slot, height), nil
}

// GetHashVal returns SHA256(t//s,x,x',height).
func (proof *DefaultProof) GetHashVal(slot uint64, height uint64) pocutil.Hash {
	var b32 [32]byte
	binary.LittleEndian.PutUint64(b32[:], slot)
	copy(b32[8:], proof.X)
	copy(b32[16:], proof.XPrime)
	binary.LittleEndian.PutUint64(b32[24:], height)

	return pocutil.SHA256(b32[:])
}

func Q1FactorDefault(bitLength int) *big.Float {
	// Note: Q1 = SIZE * BL
	bl := big.NewInt(int64(bitLength))
	size := big.NewInt(2)
	size.Exp(size, bl, nil)
	return new(big.Float).SetInt(size.Mul(size, bl))
}
