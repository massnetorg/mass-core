package chiapos

/*
#include <stdlib.h>
#include <stdio.h>

#cgo CFLAGS:

#cgo darwin,amd64 LDFLAGS: -L./libs -lchiapos_cgo-darwin-amd64
#cgo linux,amd64 LDFLAGS: -L./libs -lchiapos_cgo-linux-amd64 -lstdc++fs

#include "cpp-prover/prover.h"
*/
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/massnetorg/mass-core/logging"
)

type DiskPlotter struct {
	ptr unsafe.Pointer
}

func NewDiskPlotter() (*DiskPlotter, error) {
	var cerr *C.char
	cptr := C.NewDiskPlotter(&cerr)
	if cerr != nil {
		defer C.free(unsafe.Pointer(cerr))

		logging.CPrint(logging.INFO, "failed to new plotter", logging.LogFormat{"err": C.GoString(cerr)})

		return nil, fmt.Errorf(C.GoString(cerr))
	}
	return &DiskPlotter{
		ptr: cptr,
	}, nil
}

func (p *DiskPlotter) CreatePlotDisk(
	tmpDir, tmp2Dir, finalDir, filename string,
	k uint8, memo, plotSeed []byte,
	buffMegabytes, numBuckets, stripeSize uint32, numThreads uint8,
	noBitfield bool,
) error {
	if p.ptr == nil {
		return fmt.Errorf("nil plotter")
	}

	ctmpdir := C.CString(tmpDir)
	ctmp2dir := C.CString(tmp2Dir)
	cfinaldir := C.CString(finalDir)
	cfilename := C.CString(filename)
	cmemo := C.CBytes(memo)
	cplotseed := C.CBytes(plotSeed)
	defer func() {
		C.free(unsafe.Pointer(ctmpdir))
		C.free(unsafe.Pointer(ctmp2dir))
		C.free(unsafe.Pointer(cfinaldir))
		C.free(unsafe.Pointer(cfilename))
		C.free(cmemo)
		C.free(cplotseed)
	}()

	nobitfield := uint8(0)
	if noBitfield {
		nobitfield = 1
	}

	cerr := C.CreatePlotDisk(p.ptr,
		ctmpdir,
		ctmp2dir,
		cfinaldir,
		cfilename,
		C.uint8_t(k),
		(*C.uchar)(cmemo),
		C.uint32_t(len(memo)),
		(*C.uchar)(cplotseed),
		C.uint32_t(len(plotSeed)),
		C.uint32_t(buffMegabytes),
		C.uint32_t(numBuckets),
		C.uint32_t(stripeSize),
		C.uint8_t(numThreads),
		C.uint8_t(nobitfield),
	)
	if cerr != nil {
		defer C.free(unsafe.Pointer(cerr))
		return fmt.Errorf(C.GoString(cerr))
	}
	return nil
}

func (p *DiskPlotter) Close() error {
	if p.ptr != nil {
		C.DeleteDiskPlotter(p.ptr)
		logging.CPrint(logging.INFO, "disk plotter closed")
		p.ptr = nil
	}
	return nil
}
