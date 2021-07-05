package chiapos

const (
	// PrivateKeyBytes is the length of a BLS private key
	PrivateKeyBytes = 32

	// PublicKeyBytes is the length of a BLS public key
	PublicKeyBytes = 48

	// SignatureBytes is the length of a BLS signature
	SignatureBytes = 96
)

type PrivateKey [PrivateKeyBytes]byte
type G1Element [PublicKeyBytes]byte
type G2Element [SignatureBytes]byte

type SchemeMPLType int

const (
	SchemeMPLBasic SchemeMPLType = 1 + iota
	SchemeMPLAug
	SchemeMPLPop
)
