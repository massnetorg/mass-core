package wire

import (
	crand "crypto/rand"
	"encoding/hex"
	"math/big"
	"math/rand"
	"time"

	"github.com/massnetorg/mass-core/interfaces"
	"github.com/massnetorg/mass-core/poc"
	"github.com/massnetorg/mass-core/poc/chiapos"
	"github.com/massnetorg/mass-core/pocec"
	wirepb "github.com/massnetorg/mass-core/wire/pb"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func mockBlock(txCount int) *MsgBlock {
	txs := make([]*MsgTx, txCount)
	txs[0] = mockCoinbaseTx()
	for i := 1; i < txCount; i++ {
		txs[i] = mockTx()
	}

	blk := &MsgBlock{
		Header:       *mockHeader(1, poc.ProofTypeDefault),
		Proposals:    *mockProposalArea(),
		Transactions: txs,
	}

	for _, fpk := range blk.Proposals.PunishmentArea {
		blk.Header.BanList = append(blk.Header.BanList, fpk.PubKey)
	}

	return blk
}

func MockHeader(version uint64, proofType poc.ProofType) *BlockHeader {
	return mockHeader(version, proofType)
}

// mockHeader mocks a blockHeader.
func mockHeader(version uint64, proofType poc.ProofType) *BlockHeader {
	base := &BlockHeader{
		ChainID:         mockHash(),
		Version:         version,
		Height:          rand.Uint64(),
		Timestamp:       time.Unix(rand.Int63(), 0),
		Previous:        mockHash(),
		TransactionRoot: mockHash(),
		WitnessRoot:     mockHash(),
		ProposalRoot:    mockHash(),
		Target:          mockBigInt(),
		Challenge:       mockHash(),
		BanList:         make([]interfaces.PublicKey, 0),
	}

	var applyDefaultProof = func() {
		base.PubKey = mockPublicKey()
		base.Signature = mockSignature()
		base.Proof = &poc.DefaultProof{
			X:      mockLenBytes(3),
			XPrime: mockLenBytes(3),
			BL:     rand.Intn(20)*2 + 20,
		}
	}

	var applyChiaProof = func() {
		base.PubKey = mockPublicKeyBLS()
		base.Proof = mockChiaProof()
		base.Signature = mockSignatureBLS()
	}

	if version >= 3 && proofType == poc.ProofTypeChia {
		applyChiaProof()
	} else {
		applyDefaultProof()
	}

	if version >= 2 {
		base.BindingRoot = Hash2CommonHash(mockHash())
	}

	return base
}

// mockBigInt mocks *big.Int with 32 bytes.
func mockBigInt() *big.Int {
	return new(big.Int).SetBytes(mockLenBytes(32))
}

// mockPublicKey mocks *pocec.PublicKey.
func mockPublicKey() *pocec.PublicKey {
	priv, err := pocec.NewPrivateKey(pocec.S256())
	if err != nil {
		panic(err)
	}
	return priv.PubKey()
}

// mockSignature mocks *pocec.Signature
func mockSignature() *pocec.Signature {
	priv, err := pocec.NewPrivateKey(pocec.S256())
	if err != nil {
		panic(err)
	}
	hash := mockHash()
	sig, err := priv.Sign(hash[:])
	if err != nil {
		panic(err)
	}
	return sig
}

// mockProposalArea mocks ProposalArea.
func mockProposalArea() *ProposalArea {
	punishmentCount := rand.Intn(10)
	punishments := make([]*FaultPubKey, punishmentCount)
	for i := range punishments {
		punishments[i] = mockPunishment()
	}

	proposalCount := rand.Intn(5)
	proposals := make([]*NormalProposal, proposalCount)
	for i := range proposals {
		proposals[i] = mockProposal()
	}

	pa := new(ProposalArea)
	pa.PunishmentArea = punishments
	pa.OtherArea = proposals

	return pa
}

// mockPunishment mocks proposal in punishmentArea.
func mockPunishment() *FaultPubKey { // TODO: mock chia header
	fpk := &FaultPubKey{
		PubKey:    mockPublicKey(),
		Testimony: [2]*BlockHeader{mockHeader(1, poc.ProofTypeDefault), mockHeader(1, poc.ProofTypeDefault)},
	}
	switch pk := fpk.PubKey.(type) {
	case *pocec.PublicKey:
		fpk.Testimony[0].PubKey = pk
		fpk.Testimony[1].PubKey = pk
	case *chiapos.G1Element:
		poc.MustGetChiaProof(fpk.Testimony[0].Proof).Pos().PoolPublicKey = pk
		poc.MustGetChiaProof(fpk.Testimony[1].Proof).Pos().PoolPublicKey = pk
	}

	return fpk
}

// mockProposal mocks normal proposal.
func mockProposal() *NormalProposal {
	length := rand.Intn(30) + 10
	return &NormalProposal{
		version:      ProposalVersion,
		proposalType: typeAnyMessage,
		content:      mockLenBytes(length),
	}
}

// mockTx mocks a tx (scripts are random bytes).
func mockTx() *MsgTx {
	return &MsgTx{
		Version: 1,
		TxIn: []*TxIn{
			{
				PreviousOutPoint: OutPoint{
					Hash:  mockHash(),
					Index: rand.Uint32() % 20,
				},
				Witness:  [][]byte{mockLenBytes(rand.Intn(50) + 100), mockLenBytes(rand.Intn(50) + 100)},
				Sequence: MaxTxInSequenceNum,
			},
		},
		TxOut: []*TxOut{
			{
				Value:    rand.Int63(),
				PkScript: mockLenBytes(rand.Intn(10) + 20),
			},
		},
		LockTime: 0,
		Payload:  mockLenBytes(rand.Intn(20)),
	}
}

// mockCoinbaseTx mocks a coinbase tx.
func mockCoinbaseTx() *MsgTx {
	return &MsgTx{
		Version: 1,
		TxIn: []*TxIn{
			{
				PreviousOutPoint: OutPoint{
					Hash:  Hash{},
					Index: 0xffffffff,
				},
				Witness:  [][]byte{mockLenBytes(rand.Intn(50) + 100), mockLenBytes(rand.Intn(50) + 100)},
				Sequence: MaxTxInSequenceNum,
			},
		},
		TxOut: []*TxOut{
			{
				Value:    rand.Int63(),
				PkScript: mockLenBytes(rand.Intn(10) + 20),
			},
		},
		LockTime: 0,
		Payload:  mockLenBytes(rand.Intn(20)),
	}
}

// mockHash mocks a hash.
func mockHash() Hash {
	pb := new(wirepb.Hash)
	pb.S0 = rand.Uint64()
	pb.S1 = rand.Uint64()
	pb.S2 = rand.Uint64()
	pb.S3 = rand.Uint64()
	hash, _ := NewHashFromProto(pb)
	return *hash
}

// mockLenBytes mocks bytes with given length.
func mockLenBytes(len int) []byte {
	buf := make([]byte, len, len)
	crand.Read(buf)
	return buf
}

func mockChiaProof() *poc.ChiaProof {
	pos := &chiapos.ProofOfSpace{
		Challenge:     mockHash(),
		PoolPublicKey: mockPublicKeyBLS(),
		PuzzleHash:    mockHash(),
		PlotPublicKey: mockPublicKeyBLS(),
		KSize:         uint8(rand.Intn(19)) + 32,
		Proof:         mockLenBytes(128),
	}
	return poc.NewChiaProof(pos)
}

func mockPublicKeyBLS() *chiapos.G1Element {
	priv, err := chiapos.NewAugSchemeMPL().KeyGen(mockLenBytes(32))
	if err != nil {
		panic(err)
	}
	pub, err := priv.GetG1()
	if err != nil {
		panic(err)
	}
	return pub
}

func mockSignatureBLS() *chiapos.G2Element {
	priv, err := chiapos.NewAugSchemeMPL().KeyGen(mockLenBytes(32))
	if err != nil {
		panic(err)
	}
	sig, err := chiapos.NewAugSchemeMPL().Sign(priv, mockLenBytes(32))
	if err != nil {
		panic(err)
	}
	return sig
}

func hexToBigInt(str string) *big.Int {
	return new(big.Int).SetBytes(mustDecodeString(str))
}

func mustDecodeString(str string) []byte {
	buf, err := hex.DecodeString(str)
	if err != nil {
		panic(err)
	}
	return buf
}

func mustDecodeHash(str string) Hash {
	h, err := NewHashFromStr(str)
	if err != nil {
		panic(err)
	}
	return *h
}

func mustDecodePoCPublicKey(str string) *pocec.PublicKey {
	pub, err := pocec.ParsePubKey(mustDecodeString(str), pocec.S256())
	if err != nil {
		panic(err)
	}
	return pub
}

func mustDecodePoCSignature(str string) *pocec.Signature {
	sig, err := pocec.ParseSignature(mustDecodeString(str), pocec.S256())
	if err != nil {
		panic(err)
	}
	return sig
}
