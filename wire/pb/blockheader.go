package wirepb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/massnetorg/mass-core/poc"
)

func (m *BlockHeader) Write(w io.Writer) (int, error) {
	var version, height, timestamp [8]byte
	binary.LittleEndian.PutUint64(version[:], m.Version)
	binary.LittleEndian.PutUint64(height[:], m.Height)
	binary.LittleEndian.PutUint64(timestamp[:], uint64(m.Timestamp))

	var totalBytes = [][]byte{m.ChainID.Bytes(), version[:], height[:], timestamp[:],
		m.Previous.Bytes(), m.TransactionRoot.Bytes(), m.WitnessRoot.Bytes(),
		m.ProposalRoot.Bytes(), m.Target.Bytes(), m.Challenge.Bytes(),
		m.PubKey.Bytes(), m.Proof.Bytes(), m.Signature.Bytes()}

	for i := 0; i < len(m.BanList); i++ {
		totalBytes = append(totalBytes, m.BanList[i].Bytes())
	}

	if m.Version >= 2 {
		totalBytes = append(totalBytes, m.BindingRoot.Bytes())
	}

	return writeBytes(w, totalBytes...)
}

func (m *BlockHeader) Bytes() []byte {
	var buf bytes.Buffer
	m.Write(&buf)
	return buf.Bytes()
}

func (m *BlockHeader) WritePoC(w io.Writer) (int, error) {
	var version, height, timestamp [8]byte
	binary.LittleEndian.PutUint64(version[:], m.Version)
	binary.LittleEndian.PutUint64(height[:], m.Height)
	binary.LittleEndian.PutUint64(timestamp[:], uint64(m.Timestamp))

	var totalBytes = [][]byte{m.ChainID.Bytes(), version[:], height[:], timestamp[:],
		m.Previous.Bytes(), m.TransactionRoot.Bytes(), m.WitnessRoot.Bytes(),
		m.ProposalRoot.Bytes(), m.Target.Bytes(), m.Challenge.Bytes(), m.PubKey.Bytes(), m.Proof.Bytes()}

	for i := 0; i < len(m.BanList); i++ {
		totalBytes = append(totalBytes, m.BanList[i].Bytes())
	}

	if m.Version >= 2 {
		totalBytes = append(totalBytes, m.BindingRoot.Bytes())
	}

	return writeBytes(w, totalBytes...)
}

func (m *BlockHeader) BytesPoC() []byte {
	var buf bytes.Buffer
	m.WritePoC(&buf)
	return buf.Bytes()
}

func (m *BlockHeader) BytesChainID() []byte {
	var buf bytes.Buffer
	var version, height, timestamp [8]byte
	binary.LittleEndian.PutUint64(version[:], m.Version)
	binary.LittleEndian.PutUint64(height[:], m.Height)
	binary.LittleEndian.PutUint64(timestamp[:], uint64(m.Timestamp))

	writeBytes(&buf, version[:], height[:], timestamp[:],
		m.Previous.Bytes(), m.TransactionRoot.Bytes(), m.WitnessRoot.Bytes(),
		m.ProposalRoot.Bytes(), m.Target.Bytes(), m.Challenge.Bytes(),
		m.PubKey.Bytes(), m.Proof.Bytes())

	for i := 0; i < len(m.BanList); i++ {
		writeBytes(&buf, m.BanList[i].Bytes())
	}

	if m.Version >= 2 {
		writeBytes(&buf, m.BindingRoot.Bytes())
	}

	return buf.Bytes()
}

func ProtoToProof(pb *Proof, proof *poc.Proof) error {
	if pb == nil {
		return errors.New("nil proto proof")
	}
	switch pb.BitLength {
	case uint32(poc.ProofTypeChia):
		chia := poc.NewChiaProof(nil)
		if err := chia.Decode(pb.X); err != nil {
			return err
		}
		*proof = chia
		return nil
	case uint32(poc.ProofTypeEmpty):
		empty := poc.NewEmptyProof()
		if err := empty.Decode(pb.X); err != nil {
			return err
		}
		*proof = empty
		return nil
	default:
		dp := &poc.DefaultProof{
			X:      moveBytes(pb.X),
			XPrime: moveBytes(pb.XPrime),
			BL:     int(pb.BitLength),
		}
		*proof = dp
		return nil
	}
}

func ProofToProto(proof poc.Proof) *Proof {
	if proof == nil {
		return nil
	}
	switch proof.Type() {
	case poc.ProofTypeDefault:
		dp, err := poc.GetDefaultProof(proof)
		if err != nil {
			return nil
		}
		return &Proof{
			X:         dp.X,
			XPrime:    dp.XPrime,
			BitLength: uint32(dp.BL),
		}
	default:
		return &Proof{
			X:         proof.Encode(),
			BitLength: uint32(proof.Type()),
		}
	}
}

func (m *Proof) Bytes() []byte {
	var bl [4]byte
	binary.LittleEndian.PutUint32(bl[:], uint32(m.BitLength))
	return combineBytes(m.X, m.XPrime, bl[:])
}
