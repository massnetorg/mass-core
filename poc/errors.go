package poc

import "errors"

var (
	// ErrProofDecodeDataSize indicates that the data length of serialized proof is invalid.
	ErrProofDecodeDataSize = errors.New("invalid data length on decode proof")

	// ErrProofInvalidBitLength indicates that the BitLength of Proof is invalid.
	ErrProofInvalidBitLength = errors.New("invalid bitLength")

	// ErrProofInvalidFlipValue indicates that x and x_prime is not matched.
	ErrProofInvalidFlipValue = errors.New("invalid flip value")

	// ErrProofInvalidChallenge indicates that challenge is not matched with proof.
	ErrProofInvalidChallenge = errors.New("invalid challenge")

	// ErrProofNilChia indicates that chia pos is nil
	ErrProofNilChia = errors.New("nil chia pos")

	// ErrProofChiaNoQuality indicates that chia pos has no quality
	ErrProofChiaNoQuality = errors.New("empty chia pos quality")

	// ErrProofFilter indicates that proof not passing proof filter
	ErrProofFilter = errors.New("not passing proof filter")

	// ErrProofType indicates that proof type is mismatched
	ErrProofType = errors.New("proof type mismatched")

	// ErrProofNilItf indicates that proof interface is nil
	ErrProofNilItf = errors.New("proof")
)
