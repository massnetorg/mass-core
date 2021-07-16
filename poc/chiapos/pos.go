package chiapos

/*
#include <stdlib.h>
#include <stdio.h>

#cgo CFLAGS:
#cgo windows,amd64 LDFLAGS:  -L./libs -lchiapos_cgo
#cgo darwin,amd64 LDFLAGS: -L./libs -lchiapos_cgo-darwin-amd64
#cgo linux,amd64 LDFLAGS: -L./libs -lchiapos_cgo-linux-amd64

#include "cpp-prover/prover.h"
*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/massnetorg/mass-core/logging"
)

const (
	MinPlotSize = 32
	MaxPlotSize = 50
)

type ProofOfSpace struct {
	Challenge     [32]byte
	PoolPublicKey *G1Element
	PuzzleHash    [32]byte
	PlotPublicKey *G1Element
	KSize         uint8
	Proof         []byte
}

func (pos *ProofOfSpace) GetID() ([32]byte, error) {
	// chia/types/blockchain_format/proof_of_space.py#L28 get_plot_id
	if pos.PoolPublicKey == nil && pos.PuzzleHash == ZeroID {
		return ZeroID, errors.New("nil pool_public_key and puzzle_hash")
	}
	if pos.PoolPublicKey != nil && pos.PuzzleHash != ZeroID {
		return ZeroID, errors.New("pool_public_key and puzzle_hash are both valid")
	}
	var id [32]byte
	if pos.PoolPublicKey == nil {
		id = Hash256(bytes.Join([][]byte{pos.PuzzleHash[:], pos.PlotPublicKey.Bytes()}, nil))
	} else {
		id = Hash256(bytes.Join([][]byte{pos.PoolPublicKey.Bytes(), pos.PlotPublicKey.Bytes()}, nil))
	}
	return id, nil
}

func (pos *ProofOfSpace) Encode() []byte {
	const g1ElementSize = 48
	buf := bytes.NewBuffer(nil)
	// write challenge
	buf.Write(pos.Challenge[:])
	// write pool_public_key
	if pos.PoolPublicKey != nil {
		buf.WriteByte(1)
		b48 := make([]byte, g1ElementSize)
		copy(b48, pos.PoolPublicKey.Bytes())
		buf.Write(b48)
	} else {
		buf.WriteByte(0)
	}
	// write puzzle_hash
	if pos.PuzzleHash != ZeroID {
		buf.WriteByte(1)
		buf.Write(pos.PuzzleHash[:])
	} else {
		buf.WriteByte(0)
	}
	// write plot_public_key
	b48 := make([]byte, g1ElementSize)
	copy(b48, pos.PlotPublicKey.Bytes())
	buf.Write(b48)
	// write k_size
	buf.WriteByte(pos.KSize)
	// write proof
	b4 := make([]byte, 4)
	binary.BigEndian.PutUint32(b4, uint32(len(pos.Proof)))
	buf.Write(b4)
	buf.Write(pos.Proof)
	return buf.Bytes()
}

func (pos *ProofOfSpace) Decode(data []byte) (err error) {
	const g1ElementSize = 48
	var b byte
	var b4 [4]byte
	var b32 [32]byte
	var b48 [g1ElementSize]byte
	buf := bytes.NewReader(data)
	// read challenge
	if _, err = buf.Read(b32[:]); err != nil {
		return err
	}
	pos.Challenge = b32
	// read pool_public_key (must have this field)
	if b, err = buf.ReadByte(); err != nil {
		return err
	}
	if b == 1 {
		if _, err = buf.Read(b48[:]); err != nil {
			return err
		}
		if pos.PoolPublicKey, err = NewG1ElementFromBytes(b48[:]); err != nil {
			return err
		}
	} else {
		return errors.New("proof of space: pool_public_key is nil")
	}
	// read puzzle_hash
	if b, err = buf.ReadByte(); err != nil {
		return err
	}
	if b == 1 {
		//if _, err = buf.Read(b32[:]); err != nil {
		//	return err
		//}
		//pos.PuzzleHash = b32
		return errors.New("proof of space: puzzle_hash is not zero")
	}
	// read plot_public_key
	if _, err = buf.Read(b48[:]); err != nil {
		return err
	}
	if pos.PlotPublicKey, err = NewG1ElementFromBytes(b48[:]); err != nil {
		return err
	}
	// read k_size
	if pos.KSize, err = buf.ReadByte(); err != nil {
		return err
	}
	// read proof
	if _, err = buf.Read(b4[:]); err != nil {
		return err
	}
	pos.Proof = make([]byte, binary.BigEndian.Uint32(b4[:]))
	if n, err := buf.Read(pos.Proof); n != len(pos.Proof) && err != nil {
		return err
	}
	return nil
}

func (pos *ProofOfSpace) GetVerifiedQuality(challenge [32]byte) ([]byte, error) {
	verifier := NewProofVerifier()
	defer verifier.Free()
	pid, err := pos.GetID()
	if err != nil {
		return nil, err
	}
	if pos.KSize < MinPlotSize || pos.KSize > MaxPlotSize {
		return nil, errors.New("invalid plot k size")
	}
	if pos.Challenge != CalculatePosChallenge(pid, challenge) {
		return nil, errors.New("challenge not match")
	}
	if pass := PassPlotFilter(pid, challenge); !pass {
		return nil, errors.New("not passing plot filter")
	}
	return verifier.GetVerifiedQuality(pid[:], pos.Proof, pos.Challenge, int(pos.KSize))
}

func (pos *ProofOfSpace) GetQuality() ([]byte, error) {
	verifier := NewProofVerifier()
	defer verifier.Free()
	pid, err := pos.GetID()
	if err != nil {
		return nil, err
	}
	return verifier.GetVerifiedQuality(pid[:], pos.Proof, pos.Challenge, int(pos.KSize))
}

type ProofVerifier struct {
	verifierPtr unsafe.Pointer
}

func NewProofVerifier() *ProofVerifier {
	return &ProofVerifier{}
}

func (pv *ProofVerifier) GetVerifiedQuality(plotSeed, proof []byte, challenge [32]byte, k int) ([]byte, error) {
	if pv.verifierPtr == nil {
		pv.verifierPtr = C.NewVerifier()
	}

	seed := C.CBytes(plotSeed)
	defer C.free(seed)

	ch := C.CBytes(challenge[:])
	defer C.free(ch)

	cproof := C.CBytes(proof)
	defer C.free(cproof)

	var out *C.uchar
	var outLen C.int
	var cerr *C.char

	C.ValidateProof(pv.verifierPtr, C.uchar(k),
		(*C.uchar)(seed),
		(*C.uchar)(ch),
		(*C.uchar)(cproof), C.size_t(len(proof)),
		&out, &outLen, &cerr)
	if cerr != nil {
		defer C.free(unsafe.Pointer(cerr))
		logging.CPrint(logging.WARN, "get verified quality failed", logging.LogFormat{"err": C.GoString(cerr)})
		return nil, fmt.Errorf(C.GoString(cerr))
	}

	if out != nil {
		// TODO: crash on windows, so comment it with mem leak on windows.
		if runtime.GOOS != "windows" {
			defer C.free(unsafe.Pointer(out))
		}
		return C.GoBytes(unsafe.Pointer(out), outLen), nil
	}
	return nil, nil
}

func (pv *ProofVerifier) Free() {
	if pv.verifierPtr != nil {
		C.DeleteVerifier(pv.verifierPtr)
		pv.verifierPtr = nil
	}
}

func CalculatePlotFilterInput(plotID, challenge [32]byte) [32]byte {
	data := make([]byte, 64)
	copy(data, plotID[:])
	copy(data[32:], challenge[:])
	return Hash256(data)
}

func CalculatePosChallenge(plotID, challenge [32]byte) [32]byte {
	data := CalculatePlotFilterInput(plotID, challenge)
	return Hash256(data[:])
}

// TODO: confirm algorithm
func PassPlotFilter(plotID, challenge [32]byte) bool {
	input := CalculatePlotFilterInput(plotID, challenge)
	return (input[0] == 0) && (input[1]&0b10000000 == 0)
}
