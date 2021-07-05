package wire

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/massnetorg/mass-core/consensus"
	"github.com/massnetorg/mass-core/interfaces"
	"github.com/massnetorg/mass-core/poc"
	"github.com/massnetorg/mass-core/poc/chiapos"
	"github.com/massnetorg/mass-core/pocec"
	"github.com/massnetorg/mass-core/trie/common"
	wirepb "github.com/massnetorg/mass-core/wire/pb"
)

// BlockVersion is the current latest supported block version.
const (
	BlockVersionV1 = 1
	BlockVersionV2 = 2

	BlockVersion = BlockVersionV2
)

const MinBlockHeaderPayload = blockHeaderMinPlainSize

type BlockHeader struct {
	ChainID         Hash
	Version         uint64
	Height          uint64
	Timestamp       time.Time
	Previous        Hash
	TransactionRoot Hash
	WitnessRoot     Hash
	ProposalRoot    Hash
	Target          *big.Int
	Challenge       Hash
	PubKey          interfaces.PublicKey
	Proof           poc.Proof
	Signature       interfaces.Signature
	BanList         []interfaces.PublicKey
	BindingRoot     common.Hash // use this while header.Version >= 2
}

// blockHeaderMinPlainSize is a constant that represents the number of bytes for a block
// header.
// Length = 32(ChainID) + 8(Version) + 8(Height) + 8(Timestamp) + 32(Previous) + 32(TransactionRoot)
//        + 32(WitnessRoot)+ 32(ProposalRoot) + 32(Target) + 32(Challenge) + 33(PubKey) + 16(Proof)
//        + 72(Signature) + (n*33/48)(BanList)
//        = 369 Bytes
const blockHeaderMinPlainSize = 369

// BlockHash computes the block identifier hash for the given block header.
func (h *BlockHeader) BlockHash() Hash {
	buf, _ := h.Bytes(ID)
	return DoubleHashH(buf)
}

// Decode decodes r using the given protocol encoding into the receiver.
func (h *BlockHeader) Decode(r io.Reader, mode CodecMode) (n int, err error) {
	var buf bytes.Buffer
	n64, err := buf.ReadFrom(r)
	n = int(n64)
	if err != nil {
		return n, err
	}

	switch mode {
	case DB, Packet:
		pb := new(wirepb.BlockHeader)
		err = proto.Unmarshal(buf.Bytes(), pb)
		if err != nil {
			return n, err
		}
		return n, h.FromProto(pb)

	default:
		return n, ErrInvalidCodecMode
	}
}

// Encode encodes the receiver to w using the given protocol encoding.
func (h *BlockHeader) Encode(w io.Writer, mode CodecMode) (n int, err error) {
	pb := h.ToProto()

	switch mode {
	case DB, Packet:
		content, err := proto.Marshal(pb)
		if err != nil {
			return 0, err
		}
		return w.Write(content)

	case Plain, ID:
		// Write every elements of blockHeader
		return pb.Write(w)

	case PoCID:
		// Write elements excepts for Signature
		return pb.WritePoC(w)

	case ChainID:
		if pb.Height > 0 {
			return 0, errors.New("chain_id only be calc for genesis block")
		}
		// Write elements excepts for ChainID
		return w.Write(pb.BytesChainID())

	default:
		return 0, ErrInvalidCodecMode
	}
}

func (h *BlockHeader) Bytes(mode CodecMode) ([]byte, error) {
	return getBytes(h, mode)
}

func (h *BlockHeader) SetBytes(bs []byte, mode CodecMode) error {
	return setFromBytes(h, bs, mode)
}

func (h *BlockHeader) PlainSize() int {
	return getPlainSize(h)
}

// GetChainID calc chainID, only block with 0 height can be calc
func (h *BlockHeader) GetChainID() (Hash, error) {
	if h.Height > 0 {
		return Hash{}, errors.New(fmt.Sprintf("invalid height %d to calc chainID", h.Height))
	}
	buf, err := h.Bytes(ChainID)
	if err != nil {
		return Hash{}, err
	}
	return DoubleHashH(buf), nil
}

func NewBlockHeaderFromBytes(bhBytes []byte, mode CodecMode) (*BlockHeader, error) {
	bh := NewEmptyBlockHeader()

	err := bh.SetBytes(bhBytes, mode)
	if err != nil {
		return nil, err
	}

	return bh, nil
}

func NewEmptyBigInt() *big.Int {
	return new(big.Int).SetUint64(0)
}

func NewEmptyPoCSignature() *pocec.Signature {
	return &pocec.Signature{
		R: NewEmptyBigInt(),
		S: NewEmptyBigInt(),
	}
}

func NewEmptyPoCPublicKey() *pocec.PublicKey {
	return &pocec.PublicKey{
		X: NewEmptyBigInt(),
		Y: NewEmptyBigInt(),
	}
}

func NewEmptyBLSPublicKey() *chiapos.G1Element {
	return chiapos.NewG1Element()
}

func NewEmptyBLSSignature() *chiapos.G2Element {
	return chiapos.NewG2Element()
}

func NewEmptyBlockHeader() *BlockHeader {
	return &BlockHeader{
		Timestamp: time.Unix(0, 0),
		Target:    NewEmptyBigInt(),
		PubKey:    NewEmptyPoCPublicKey(),
		Proof:     poc.NewEmptyProof(),
		Signature: NewEmptyPoCSignature(),
		BanList:   make([]interfaces.PublicKey, 0),
	}
}

// PoCHash generate hash of all PoC needed elements in block header
func (h *BlockHeader) PoCHash() (Hash, error) {
	buf, err := h.Bytes(PoCID)
	if err != nil {
		return Hash{}, err
	}

	return DoubleHashH(buf), nil
}

// ToProto get proto BlockHeader from wire BlockHeader
func (h *BlockHeader) ToProto() *wirepb.BlockHeader {
	banList := make([]*wirepb.PublicKey, len(h.BanList))
	for i, pub := range h.BanList {
		banList[i] = wirepb.PublicKeyToProto(pub)
	}

	bh := &wirepb.BlockHeader{
		ChainID:         h.ChainID.ToProto(),
		Version:         h.Version,
		Height:          h.Height,
		Timestamp:       uint64(h.Timestamp.Unix()),
		Previous:        h.Previous.ToProto(),
		TransactionRoot: h.TransactionRoot.ToProto(),
		WitnessRoot:     h.WitnessRoot.ToProto(),
		ProposalRoot:    h.ProposalRoot.ToProto(),
		Target:          wirepb.BigIntToProto(h.Target),
		Challenge:       h.Challenge.ToProto(),
		PubKey:          wirepb.PublicKeyToProto(h.PubKey),
		Proof:           wirepb.ProofToProto(h.Proof),
		Signature:       wirepb.SignatureToProto(h.Signature),
		BanList:         banList,
	}

	if h.Version >= BlockVersionV2 {
		bh.BindingRoot = CommonHash2Hash(&h.BindingRoot).ToProto()
	}

	return bh
}

// FromProto load proto BlockHeader into wire BlockHeader
func (h *BlockHeader) FromProto(pb *wirepb.BlockHeader) error {
	if pb == nil {
		return errors.New("nil proto block_header")
	}
	var unmarshalHash = func(h []*Hash, pb []*wirepb.Hash) (err error) {
		for i := range h {
			if err = h[i].FromProto(pb[i]); err != nil {
				return err
			}
		}
		return nil
	}
	chainID, previous, transactionRoot, witnessRoot, proposalRoot, challenge := new(Hash), new(Hash), new(Hash), new(Hash), new(Hash), new(Hash)
	var err error
	if err = unmarshalHash([]*Hash{chainID, previous, transactionRoot, witnessRoot, proposalRoot, challenge},
		[]*wirepb.Hash{pb.ChainID, pb.Previous, pb.TransactionRoot, pb.WitnessRoot, pb.ProposalRoot, pb.Challenge, pb.BindingRoot}); err != nil {
		return err
	}
	target := new(big.Int)
	if err = wirepb.ProtoToBigInt(pb.Target, target); err != nil {
		return err
	}
	pub, err := wirepb.ProtoToPublicKey(pb.PubKey)
	if err != nil {
		return err
	}
	proof := new(poc.Proof)
	if err = wirepb.ProtoToProof(pb.Proof, proof); err != nil {
		return err
	}
	sig, err := wirepb.ProtoToSignature(pb.Signature)
	if err != nil {
		return err
	}
	banList := make([]interfaces.PublicKey, len(pb.BanList))
	for i, pk := range pb.BanList {
		pub, err := wirepb.ProtoToPublicKey(pk)
		if err != nil {
			return err
		}
		banList[i] = pub
	}
	bindingRoot := common.Hash{}
	if pb.Version >= BlockVersionV2 {
		br := new(Hash)
		if err = br.FromProto(pb.BindingRoot); err != nil {
			return err
		}
		bindingRoot = Hash2CommonHash(*br)
	}

	h.ChainID = *chainID
	h.Version = pb.Version
	h.Height = pb.Height
	h.Timestamp = time.Unix(int64(pb.Timestamp), 0)
	h.Previous = *previous
	h.TransactionRoot = *transactionRoot
	h.WitnessRoot = *witnessRoot
	h.ProposalRoot = *proposalRoot
	h.Target = target
	h.Challenge = *challenge
	h.PubKey = pub
	h.Proof = *proof
	h.Signature = sig
	h.BanList = banList
	h.BindingRoot = bindingRoot

	return h.CheckVersionConstraint()
}

// NewBlockHeaderFromProto get wire BlockHeader from proto BlockHeader
func NewBlockHeaderFromProto(pb *wirepb.BlockHeader) (*BlockHeader, error) {
	h := new(BlockHeader)
	err := h.FromProto(pb)
	if err != nil {
		return nil, err
	}
	return h, nil
}

// ============ Methods below hide differences between MASS and Chia ===============

// Quality
func (h *BlockHeader) Quality() *big.Int {
	return h.Proof.Quality(uint64(h.Timestamp.Unix())/poc.PoCSlot, h.Height)
}

func (h *BlockHeader) PublicKey() interfaces.PublicKey {
	return h.PubKey
}

// Both old and new public keys are allowed packed
func (h *BlockHeader) BannedPublicKeys() (banned []interfaces.PublicKey) {
	for _, ban := range h.BanList {
		banned = append(banned, ban)
	}
	return banned
}

func (h *BlockHeader) SetBanListFromProposals(proposals []*FaultPubKey) error {
	if len(proposals) > 0 {
		firstBl := proposals[0].Testimony[0].Proof.BitLength()
		for _, proposal := range proposals {
			if proposal.Testimony[0].Proof.BitLength() != firstBl {
				return fmt.Errorf("multiple bitlengths found when setting banlist")
			}
			h.BanList = append(h.BanList, proposal.PubKey)
		}
	}
	return nil
}

func (h *BlockHeader) VerifySig() (bool, error) {
	pocHash, err := h.PoCHash()
	if err != nil {
		return false, err
	}
	dataHash := HashH(pocHash[:])

	if pub, ok := h.PubKey.(*pocec.PublicKey); ok {
		if sig, ok := h.Signature.(*pocec.Signature); ok {
			return sig.Verify(dataHash[:], pub), nil
		} else {
			return false, errUnknownSignatureType
		}
	}

	if pub, ok := h.PubKey.(*chiapos.G1Element); ok {
		if sig, ok := h.Signature.(*chiapos.G2Element); ok {
			return chiapos.NewAugSchemeMPL().Verify(pub, dataHash[:], sig)
		} else {
			return false, errUnknownSignatureType
		}
	}

	return false, errUnknownPubKeyType
}

func (h *BlockHeader) CheckVersionConstraint() error {
	switch h.Version {
	case 0:
		return fmt.Errorf("%w: %d", errWrongBlockVersion, 0)
	case uint64(BlockVersionV1):
		return h.checkVersionConstraintV1()
	default:
		return h.checkVersionConstraintV2()
	}
}

func (h *BlockHeader) checkVersionConstraintV1() error {
	if !isS256PublicKey(h.PubKey) {
		return errMisusePubKeyType
	}
	if h.Proof.Type() != poc.ProofTypeDefault {
		return errMisuseProofType
	}
	if !isS256Signature(h.Signature) {
		return errMisuseSignatureType
	}
	for _, pub := range h.BanList {
		if !isS256PublicKey(pub) {
			return errMisusePubKeyType
		}
	}
	if !isEmptyBindingRoot(h.BindingRoot) {
		return errMisuseBindingRoot
	}
	return nil
}

func (h *BlockHeader) checkVersionConstraintV2() error {
	switch h.Proof.Type() {
	case poc.ProofTypeDefault:
		if !isS256PublicKey(h.PubKey) {
			return errMisusePubKeyType
		}
		if !isS256Signature(h.Signature) {
			return errMisuseSignatureType
		}
	case poc.ProofTypeChia:
		if !isBLSPublicKey(h.PubKey) {
			return errMisusePubKeyType
		}
		if !isBLSSignature(h.Signature) {
			return errMisuseSignatureType
		}
	default:
		return errMisuseProofType
	}
	if h.Height < consensus.MASSIP0002Height {
		for _, pub := range h.BanList {
			if !isS256PublicKey(pub) {
				return errMisusePubKeyType
			}
		}
	}
	return nil
}

func isS256PublicKey(pub interfaces.PublicKey) bool {
	_, ok := pub.(*pocec.PublicKey)
	return ok
}

func isS256Signature(sig interfaces.Signature) bool {
	_, ok := sig.(*pocec.Signature)
	return ok
}

func isBLSPublicKey(pub interfaces.PublicKey) bool {
	_, ok := pub.(*chiapos.G1Element)
	return ok
}

func isBLSSignature(sig interfaces.Signature) bool {
	_, ok := sig.(*chiapos.G2Element)
	return ok
}

func isEmptyBindingRoot(root common.Hash) bool {
	return root == common.Hash{}
}
