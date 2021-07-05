package poc

import (
	"math/big"

	"github.com/massnetorg/mass-core/poc/pocutil"
)

type EmptyProof struct{}

func NewEmptyProof() *EmptyProof {
	return &EmptyProof{}
}

func (proof *EmptyProof) Type() ProofType {
	return ProofTypeEmpty
}

func (proof *EmptyProof) BitLength() int {
	return int(ProofTypeEmpty)
}

func (proof *EmptyProof) Encode() []byte {
	return nil
}

func (proof *EmptyProof) Decode([]byte) error {
	return nil
}

func (proof *EmptyProof) Quality(slot, height uint64) *big.Int {
	return big.NewInt(0)
}

func (proof *EmptyProof) Verify(plotSeed pocutil.Hash, challenge pocutil.Hash, filter bool) error {
	return nil
}

func (proof *EmptyProof) VerifiedQuality(plotSeed pocutil.Hash, challenge pocutil.Hash, filter bool, slot, height uint64) (*big.Int, error) {
	return big.NewInt(0), nil
}
