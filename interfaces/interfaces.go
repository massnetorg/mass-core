package interfaces

type PublicKey interface {
	SerializeCompressed() []byte
	SerializeUncompressed() []byte
}

type Signature interface {
	Serialize() []byte
}
