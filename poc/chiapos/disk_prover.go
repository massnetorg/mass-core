package chiapos

/*
#include <stdlib.h>
#include <stdio.h>

#cgo CFLAGS:

#cgo darwin,amd64 LDFLAGS: -L./libs -lchiapos_cgo-darwin-amd64 -lfse-darwin-amd64
#cgo linux,amd64 LDFLAGS: -L./libs -lchiapos_cgo-linux-amd64 -lfse-linux-amd64 -lm

#include "cpp-prover/prover.h"
*/
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/massnetorg/mass-core/logging"
)

var ZeroID = [32]byte{}

type DiskProver struct {
	ptr      unsafe.Pointer
	info     *PlotInfo
	filename string
	memo     []byte
	id       [32]byte
	k        uint8
}

type PlotInfo struct {
	PoolPublicKey   *G1Element
	PuzzleHash      [32]byte
	FarmerPublicKey *G1Element
	MasterSk        *PrivateKey
	LocalSk         *PrivateKey
	PlotPublicKey   *G1Element
}

func NewDiskProver(filename string, loadPlotInfo bool) (*DiskProver, error) {
	cstr := C.CString(filename)
	defer C.free(unsafe.Pointer(cstr))

	var cerr *C.char
	cdp := C.NewDiskProver(cstr, &cerr)
	if cerr != nil {
		defer C.free(unsafe.Pointer(cerr))

		logging.CPrint(logging.INFO, "open disk prover failed", logging.LogFormat{"err": C.GoString(cerr)})

		return nil, fmt.Errorf(C.GoString(cerr))
	}

	logging.CPrint(logging.INFO, "disk prover open", logging.LogFormat{"filename": filename})

	dp := &DiskProver{
		ptr:      cdp,
		filename: filename,
	}

	if loadPlotInfo {
		var err error
		if _, err = dp.getPlotInfo(); err != nil {
			dp.Close()
			return nil, fmt.Errorf("failed to get plot info: %w", err)
		}
		if _, err = dp.getMemo(); err != nil {
			dp.Close()
			return nil, fmt.Errorf("failed to get memo: %w", err)
		}
		if _, err = dp.getID(); err != nil {
			dp.Close()
			return nil, fmt.Errorf("failed to get id: %w", err)
		}
		if _, err = dp.getSize(); err != nil {
			dp.Close()
			return nil, fmt.Errorf("failed to get size: %w", err)
		}
	}

	return dp, nil
}

func (dp *DiskProver) Memo() []byte {
	return dp.memo
}

func (dp *DiskProver) getMemo() ([]byte, error) {
	if dp.ptr == nil {
		return nil, fmt.Errorf("nil prover")
	}
	if len(dp.memo) == 0 {
		var out *C.uchar
		var length C.int

		C.GetMemo(dp.ptr, &out, &length)
		if out != nil {
			defer C.free(unsafe.Pointer(out))
			dp.memo = C.GoBytes(unsafe.Pointer(out), length)
		}
	}
	return dp.memo, nil
}

func (dp *DiskProver) PlotInfo() *PlotInfo {
	return dp.info
}

func (dp *DiskProver) getPlotInfo() (*PlotInfo, error) {
	memo, err := dp.getMemo()
	if err != nil {
		return nil, err
	}

	var info *PlotInfo
	switch len(memo) {
	case 48 + 48 + 32:
		// This is a public key memo
		ppk, err := NewG1ElementFromBytes(memo[:48])
		if err != nil {
			return nil, err
		}
		fpk, err := NewG1ElementFromBytes(memo[48:96])
		if err != nil {
			return nil, err
		}
		lmsk, err := NewPrivateKeyFromBytes(memo[96:])
		if err != nil {
			return nil, err
		}
		info = &PlotInfo{
			PoolPublicKey:   ppk,
			FarmerPublicKey: fpk,
			MasterSk:        lmsk,
		}
	case 32 + 48 + 32:
		// This is a pool_contract_puzzle_hash memo
		fpk, err := NewG1ElementFromBytes(memo[32:80])
		if err != nil {
			return nil, err
		}
		lmsk, err := NewPrivateKeyFromBytes(memo[80:])
		if err != nil {
			return nil, err
		}
		info = &PlotInfo{
			FarmerPublicKey: fpk,
			MasterSk:        lmsk,
		}
		copy(info.PuzzleHash[:], memo[:32])
	default:
		return nil, fmt.Errorf("memo has invalid number of bytes %d", len(memo))
	}
	info.LocalSk, err = MasterSkToLocalSk(info.MasterSk)
	if err != nil {
		return nil, err
	}
	localPk, err := info.LocalSk.GetG1()
	if err != nil {
		return nil, err
	}
	info.PlotPublicKey, err = localPk.Add(info.FarmerPublicKey)
	if err != nil {
		return nil, err
	}
	dp.info = info
	return info, nil
}

func (dp *DiskProver) ID() [32]byte {
	return dp.id
}

func (dp *DiskProver) getID() ([32]byte, error) {
	if dp.ptr == nil {
		return [32]byte{}, fmt.Errorf("nil prover")
	}

	if dp.id == ZeroID {
		var out *C.uchar
		var length C.int

		C.GetID(dp.ptr, &out, &length)
		if out != nil {
			defer C.free(unsafe.Pointer(out))

			buf := C.GoBytes(unsafe.Pointer(out), length)
			copy(dp.id[:], buf)
		}
	}
	return dp.id, nil
}

func (dp *DiskProver) Size() uint8 {
	if dp.k == 0 && dp.ptr != nil {
		dp.k, _ = dp.getSize()
	}
	return dp.k
}

func (dp *DiskProver) getSize() (uint8, error) {
	if dp.ptr == nil {
		return 0, fmt.Errorf("nil prover")
	}
	if dp.k == 0 {
		var out C.uchar
		C.GetSize(dp.ptr, &out)
		dp.k = uint8(out)
	}
	return dp.k, nil
}

func (dp *DiskProver) Filename() string {
	return dp.filename
}

func (dp *DiskProver) GetQualitiesForChallenge(challenge [32]byte) ([][]byte, error) {
	if dp.ptr == nil {
		return nil, fmt.Errorf("nil prover")
	}

	cPtr := C.CBytes(challenge[:])
	defer C.free(cPtr)

	var out *C.uchar
	var num C.int
	var catLen C.int

	cerr := C.GetQualitiesForChallenge(dp.ptr, (*C.uchar)(cPtr), &out, &catLen, &num)
	if cerr != nil {
		defer C.free(unsafe.Pointer(cerr))
		return nil, fmt.Errorf(C.GoString(cerr))
	}

	defer C.free(unsafe.Pointer(out))

	ret := make([][]byte, 0, int(num))
	cat := C.GoBytes(unsafe.Pointer(out), catLen)
	if len(cat) != 32*int(num) {
		return nil, fmt.Errorf("illegal length of returned bytes %d, number of qualities %d", len(cat), int(num))
	}
	for i := 0; i < int(num); i++ {
		ret = append(ret, cat[i*32:(i+1)*32])
	}
	return ret, nil
}

func (dp *DiskProver) GetFullProof(challenge [32]byte, index uint32) ([]byte, error) {
	if dp.ptr == nil {
		return nil, fmt.Errorf("nil prover")
	}

	cPtr := C.CBytes(challenge[:])
	defer C.free(cPtr)

	var out *C.uchar
	var length C.int
	var cerr *C.char

	C.GetFullProof(dp.ptr, (*C.uchar)(cPtr), C.uint(index), &out, &length, &cerr)
	if cerr != nil {
		defer C.free(unsafe.Pointer(cerr))
		logging.CPrint(logging.INFO, "get full proof failed", logging.LogFormat{"err": C.GoString(cerr)})
		return nil, fmt.Errorf(C.GoString(cerr))
	}

	defer C.free(unsafe.Pointer(out))

	return C.GoBytes(unsafe.Pointer(out), length), nil
}

func (dp *DiskProver) Close() error {
	if dp.ptr != nil {
		C.DeleteDiskProver(dp.ptr)
		logging.CPrint(logging.INFO, "disk prover closed", logging.LogFormat{"filename": dp.filename})
		dp.ptr = nil
	}
	return nil
}
