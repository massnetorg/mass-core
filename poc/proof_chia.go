package poc

import (
	"encoding/binary"
	"math/big"

	"github.com/massnetorg/mass-core/poc/chiapos"
	"github.com/massnetorg/mass-core/poc/pocutil"
)

func ChiaPlotSize(k int) uint64 {
	return uint64(2*k+1) * (uint64(1) << (uint(k) - 1))
}

type ChiaProof struct {
	pos *chiapos.ProofOfSpace
}

func NewChiaProof(pos *chiapos.ProofOfSpace) *ChiaProof {
	return &ChiaProof{pos: pos}
}

func GetChiaProof(proof Proof) (*ChiaProof, error) {
	if proof == nil {
		return nil, ErrProofNilItf
	}
	chia, ok := proof.(*ChiaProof)
	if !ok {
		return nil, ErrProofType
	}
	return chia, nil
}

func MustGetChiaProof(proof Proof) *ChiaProof {
	return proof.(*ChiaProof)
}

func GetChiaPoolPublicKey(proof Proof) (*chiapos.G1Element, error) {
	chiaProof, err := GetChiaProof(proof)
	if err != nil {
		return nil, err
	}
	if chiaProof.pos == nil {
		return nil, ErrProofNilChia
	}
	return chiaProof.pos.PoolPublicKey, nil
}

func GetChiaPlotID(proof Proof) ([32]byte, error) {
	chiaProof, err := GetChiaProof(proof)
	if err != nil {
		return [32]byte{}, err
	}
	if chiaProof.pos == nil {
		return [32]byte{}, ErrProofNilChia
	}
	return chiaProof.pos.GetID()
}

func MustGetChiaPoolPublicKey(proof Proof) *chiapos.G1Element {
	return MustGetChiaProof(proof).pos.PoolPublicKey
}

func (proof *ChiaProof) Type() ProofType {
	return ProofTypeChia
}

func (proof *ChiaProof) BitLength() int {
	if proof.pos == nil {
		return int(ProofTypeChia)
	}
	return int(proof.pos.KSize)
}

// Encode encodes proof to N + 1 bytes:
// |  Chia PoS | ProofTypeChia |
// |  N bytes  | 1 byte    |
func (proof *ChiaProof) Encode() []byte {
	if proof.pos == nil {
		return nil
	}
	bs := proof.pos.Encode()
	data := make([]byte, len(bs)+1)
	copy(data, bs)
	data[len(data)-1] = uint8(ProofTypeChia)
	return data
}

// decodeChia decodes proof from N + 1 bytes slice:
// |  Chia PoS | ProofTypeChia |
// |  N bytes  | 1 byte    |
func (proof *ChiaProof) Decode(data []byte) error {
	if len(data) < 1 {
		return ErrProofDecodeDataSize
	}
	if data[len(data)-1] != uint8(ProofTypeChia) {
		return ErrProofInvalidBitLength
	}
	chiaPos := &chiapos.ProofOfSpace{}
	if err := chiaPos.Decode(data[:len(data)-1]); err != nil {
		return err
	}
	proof.pos = chiaPos
	return nil
}

func (proof *ChiaProof) Quality(slot, height uint64) *big.Int {
	if proof.pos == nil {
		return big.NewInt(0)
	}
	chiaQuality, err := proof.pos.GetQuality()
	if err != nil {
		return big.NewInt(0)
	}
	hashVal := HashValChia(chiaQuality, slot, height)
	q1 := Q1FactorChia(proof.pos.KSize)
	return GetQuality(q1, hashVal)
}

// verifyProofChia verifies proof:
// (1) make sure BitLength is Valid. Should be integer even number in [24, 40].
// (2) perform function P on x and x_prime, the corresponding result
//     y and y_prime should be a bit-flip pair.
// (3) perform function F on x and x_prime, the result z should
//     be equal to the bit-length-cut challenge.
// It returns nil when proof is verified.
func (proof *ChiaProof) Verify(useless, challenge pocutil.Hash, filter bool) error {
	if proof.pos == nil {
		return ErrProofNilChia
	}

	quality, err := proof.pos.GetVerifiedQuality(challenge)
	if err != nil {
		return err
	}

	if len(quality) == 0 {
		return ErrProofChiaNoQuality
	}

	return nil
}

func (proof *ChiaProof) VerifiedQuality(useless, challenge pocutil.Hash, filter bool, slot, height uint64) (*big.Int, error) {
	if err := proof.Verify(useless, challenge, filter); err != nil {
		return nil, err
	}
	return proof.Quality(slot, height), nil
}

func (proof *ChiaProof) Pos() *chiapos.ProofOfSpace {
	return proof.pos
}

// HashValChia returns SHA256(t//s, chia_quality, height).
func HashValChia(chiaQuality []byte, slot, height uint64) pocutil.Hash {
	data := make([]byte, len(chiaQuality)+8*2)
	binary.LittleEndian.PutUint64(data, slot)
	copy(data[8:], chiaQuality)
	binary.LittleEndian.PutUint64(data[8+len(chiaQuality):], height)
	return pocutil.SHA256(data)
}

func Q1FactorChia(k uint8) *big.Float {
	a := big.NewFloat(float64(int64(1) << (k - 1)))
	a.Mul(a, big.NewFloat(4*float64(2*k+1)))
	return a.Mul(a, big.NewFloat(QualityConstantMASSIP0002*QualityConstantMASSValidity))
}
