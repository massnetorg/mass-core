package chiapos

/*
#include <stdlib.h>
#include <stdio.h>

#cgo CFLAGS:
#cgo windows,amd64 LDFLAGS: -L./libs -lbls_cgo-windows-amd64 -lbls-windows-amd64 -lstdc++
#cgo darwin,amd64 LDFLAGS: -L./libs -lbls_cgo-darwin-amd64 -lbls-darwin-amd64 -lstdc++
#cgo linux,amd64 LDFLAGS: -L./libs -lbls_cgo-linux-amd64 -lbls-linux-amd64 -lstdc++

#include "cpp-bls/cgo-bindings/bls-wrapper.h"
*/
import "C"
import (
	"fmt"
	"unsafe"
)

//===============PrivateKey===============

func getCPrivateKeyPtr(bytes []byte) (unsafe.Pointer, error) {
	cbuf := C.CBytes(bytes)
	defer C.free(cbuf)

	var cerr *C.char
	ptr := C.bls_PrivateKey_from_bytes((*C.char)(cbuf), C.size_t(len(bytes)), &cerr)
	if cerr != nil {
		defer C.free(unsafe.Pointer(cerr))
		return nil, fmt.Errorf(C.GoString(cerr))
	}
	return ptr, nil
}

func NewPrivateKeyFromBytes(bytes []byte) (*PrivateKey, error) {
	ptr, err := getCPrivateKeyPtr(bytes)
	if err != nil {
		return nil, err
	}
	C.bls_PrivateKey_free(ptr)

	var sk PrivateKey
	copy(sk[:], bytes)
	return &sk, nil
}

func (k *PrivateKey) Bytes() []byte {
	return k[:]
}

func (k *PrivateKey) GetG1() (*G1Element, error) {
	cbuf := C.CBytes(k[:])
	defer C.free(cbuf)

	var out *C.uchar
	var length C.int

	if cerr := C.bls_PrivateKey_get_g1((*C.char)(cbuf), &out, &length); cerr != nil {
		defer C.free(unsafe.Pointer(cerr))
		return nil, fmt.Errorf(C.GoString(cerr))
	}

	return convertCBytesToG1Element(out, length)
}

func (k *PrivateKey) Copy() *PrivateKey {
	cp := *k
	return &cp
}

func (k *PrivateKey) Equals(target *PrivateKey) bool {
	if k == target {
		return true
	}
	if k == nil || target == nil {
		return false
	}
	return *k == *target
}

//===============Util===============

// Hash256 return zero if no data
func Hash256(data []byte) (hash [32]byte) {
	if len(data) > 0 {
		buf := C.CBytes(data)
		defer C.free(buf)

		var out *C.uchar
		C.bls_Util_hash256((*C.char)(buf), C.size_t(len(data)), &out)
		if out != nil {
			defer C.free(unsafe.Pointer(out))
			gobytes := C.GoBytes(unsafe.Pointer(out), 32)
			copy(hash[:], gobytes)
		}
	}
	return
}

func AggregatePrivateKey(sks ...*PrivateKey) (*PrivateKey, error) {
	if len(sks) == 0 {
		return nil, fmt.Errorf("no sk to be aggregated")
	}
	ptrs := make([]unsafe.Pointer, 0, len(sks))
	defer func() {
		for _, ptr := range ptrs {
			C.bls_PrivateKey_free(ptr)
		}
	}()
	for _, sk := range sks {
		if sk == nil {
			return nil, fmt.Errorf("nil sk found")
		}
		ptr, err := getCPrivateKeyPtr(sk[:])
		if err != nil {
			return nil, err
		}
		ptrs = append(ptrs, ptr)
	}

	aggPtr := C.bls_PrivateKey_aggregate(&ptrs[0], C.size_t(len(ptrs)))
	defer C.bls_PrivateKey_free(aggPtr)

	// get bytes
	var out *C.uchar
	var length C.int
	C.bls_PrivateKey_to_bytes(aggPtr, &out, &length)

	return convertCBytesToPrivateKey(out, length)
}

func convertCBytesToG2Element(cbytes *C.uchar, length C.int) (*G2Element, error) {
	if cbytes != nil {
		defer C.free(unsafe.Pointer(cbytes))
	} else {
		return nil, fmt.Errorf("nil bytes to convert")
	}
	bytes := C.GoBytes(unsafe.Pointer(cbytes), length)
	if len(bytes) != SignatureBytes {
		return nil, fmt.Errorf("got invalid signature length %d", len(bytes))
	}
	var sig G2Element
	copy(sig[:], bytes)
	return &sig, nil
}

func convertCBytesToG1Element(cbytes *C.uchar, length C.int) (*G1Element, error) {
	if cbytes != nil {
		defer C.free(unsafe.Pointer(cbytes))
	} else {
		return nil, fmt.Errorf("nil bytes to convert")
	}
	bytes := C.GoBytes(unsafe.Pointer(cbytes), length)
	if len(bytes) != PublicKeyBytes {
		return nil, fmt.Errorf("got invalid public key length %d", len(bytes))
	}
	var pk G1Element
	copy(pk[:], bytes)
	return &pk, nil
}

func convertCBytesToPrivateKey(cbytes *C.uchar, length C.int) (*PrivateKey, error) {
	if cbytes != nil {
		defer C.free(unsafe.Pointer(cbytes))
	} else {
		return nil, fmt.Errorf("nil bytes to convert")
	}
	bytes := C.GoBytes(unsafe.Pointer(cbytes), length)
	if len(bytes) != PrivateKeyBytes {
		return nil, fmt.Errorf("got invalid private key length %d", len(bytes))
	}
	var sk PrivateKey
	copy(sk[:], bytes)
	return &sk, nil
}

//===============Public Key / G1Element===============

func getCG1ElementPtr(bytes []byte) (unsafe.Pointer, error) {
	buf := C.CBytes(bytes)
	defer C.free(buf)

	var cerr *C.char
	ptr := C.bls_G1Element_from_bytes((*C.char)(buf), C.size_t(len(bytes)), &cerr)
	if cerr != nil {
		defer C.free(unsafe.Pointer(cerr))
		return nil, fmt.Errorf(C.GoString(cerr))
	}
	return ptr, nil
}

// Initialization to point at infinity
func NewG1Element() *G1Element {
	var out *C.uchar
	var length C.int
	C.bls_G1Element(&out, &length)

	g1, _ := convertCBytesToG1Element(out, length) // TODO: error?
	return g1
}

func NewG1ElementGenerator() *G1Element {
	var out *C.uchar
	var length C.int
	C.bls_G1Element_generator(&out, &length)

	g1, _ := convertCBytesToG1Element(out, length) // TODO: error?
	return g1
}

func NewG1ElementFromBytes(bytes []byte) (*G1Element, error) {
	ptr, err := getCG1ElementPtr(bytes)
	if err != nil {
		return nil, err
	}
	C.bls_G1Element_free(ptr)

	var g1 G1Element
	copy(g1[:], bytes)
	return &g1, nil
}

func (e *G1Element) Bytes() []byte {
	return e[:]
}

func (e *G1Element) SerializeCompressed() []byte {
	return e.Bytes()
}

// no difference with SerializeCompressed
func (e *G1Element) SerializeUncompressed() []byte {
	return e.Bytes()
}

func (e *G1Element) Equals(target *G1Element) bool {
	if e == target {
		return true
	}
	if e == nil || target == nil {
		return false
	}
	return *e == *target
}

func (e *G1Element) Add(target *G1Element) (*G1Element, error) {
	if e == nil || target == nil {
		return nil, fmt.Errorf("nil param found")
	}

	eBuf := C.CBytes(e[:])
	defer C.free(eBuf)
	tBuf := C.CBytes(target[:])
	defer C.free(tBuf)

	var out *C.uchar
	var length C.int
	cerr := C.bls_G1Element_add((*C.char)(eBuf), (*C.char)(tBuf), &out, &length)
	if cerr != nil {
		defer C.free(unsafe.Pointer(cerr))
		return nil, fmt.Errorf(C.GoString(cerr))
	}

	return convertCBytesToG1Element(out, length)
}

func (e *G1Element) Copy() *G1Element {
	cp := *e
	return &cp
}

// func (e *G1Element) GetFingerprint() uint32 {
// 	return uint32(C.bls_G1Element_get_fingerprint(e.ptr))
// }

//===============G2Element / Signature===============

func getCG2ElementPtr(bytes []byte) (unsafe.Pointer, error) {
	buf := C.CBytes(bytes)
	defer C.free(buf)

	var cerr *C.char
	ptr := C.bls_G2Element_from_bytes((*C.char)(buf), C.size_t(len(bytes)), &cerr)
	if cerr != nil {
		defer C.free(unsafe.Pointer(cerr))
		return nil, fmt.Errorf(C.GoString(cerr))
	}
	return ptr, nil
}

// Initialization to point at infinity
func NewG2Element() *G2Element {
	var out *C.uchar
	var length C.int
	C.bls_G2Element(&out, &length)

	g2, _ := convertCBytesToG2Element(out, length) // TODO: error?
	return g2
}

func NewG2ElementGenerator() *G2Element {
	var out *C.uchar
	var length C.int
	C.bls_G2Element_generator(&out, &length)

	g2, _ := convertCBytesToG2Element(out, length) // TODO: error?
	return g2
}

func NewG2ElementFromBytes(bytes []byte) (*G2Element, error) {
	ptr, err := getCG2ElementPtr(bytes)
	if err != nil {
		return nil, err
	}
	C.bls_G2Element_free(ptr)

	var g2 G2Element
	copy(g2[:], bytes)
	return &g2, nil
}

func (e *G2Element) Bytes() []byte {
	return e[:]
}

func (e *G2Element) Serialize() []byte {
	return e.Bytes()
}

func (e *G2Element) Equals(target *G2Element) bool {
	if e == target {
		return true
	}
	if e == nil || target == nil {
		return false
	}
	return *e == *target
}

func (e *G2Element) Add(target *G2Element) (*G2Element, error) {
	if e == nil || target == nil {
		return nil, fmt.Errorf("nil param found")
	}

	eBuf := C.CBytes(e[:])
	defer C.free(eBuf)
	tBuf := C.CBytes(target[:])
	defer C.free(tBuf)

	var out *C.uchar
	var length C.int
	cerr := C.bls_G2Element_add((*C.char)(eBuf), (*C.char)(tBuf), &out, &length)
	if cerr != nil {
		defer C.free(unsafe.Pointer(cerr))
		return nil, fmt.Errorf(C.GoString(cerr))
	}

	return convertCBytesToG2Element(out, length)
}

func (e *G2Element) Copy() *G2Element {
	cp := *e
	return &cp
}

//===============  SchemeMPL  ===============

func SkToG1(schemeType SchemeMPLType, sk *PrivateKey) (*G1Element, error) {
	bufSk := C.CBytes(sk[:])
	defer C.free(bufSk)

	var out *C.uchar
	var length C.int
	if cerr := C.bls_SchemeMPL_sk_to_g1(C.size_t(schemeType), (*C.char)(bufSk), &out, &length); cerr != nil {
		defer C.free(unsafe.Pointer(cerr))
		return nil, fmt.Errorf(C.GoString(cerr))
	}

	return convertCBytesToG1Element(out, length)
}

func KeyGen(schemeType SchemeMPLType, seed []byte) (*PrivateKey, error) {
	buf := C.CBytes(seed)
	defer C.free(buf)

	var out *C.uchar
	var length C.int
	if cerr := C.bls_SchemeMPL_key_gen(C.size_t(schemeType), (*C.char)(buf), C.size_t(len(seed)), &out, &length); cerr != nil {
		defer C.free(unsafe.Pointer(cerr))
		return nil, fmt.Errorf(C.GoString(cerr))
	}

	return convertCBytesToPrivateKey(out, length)
}

// TODO: check param
func DeriveChildSk(schemeType SchemeMPLType, unhardened bool, sk *PrivateKey, index int) (*PrivateKey, error) {
	buf := C.CBytes(sk[:])
	defer C.free(buf)

	unhardenType := 0
	if unhardened {
		unhardenType = 1
	}

	var out *C.uchar
	var length C.int
	if cerr := C.bls_SchemeMPL_derive_child_sk(C.size_t(schemeType), C.size_t(unhardenType), (*C.char)(buf), C.int(index), &out, &length); cerr != nil {
		defer C.free(unsafe.Pointer(cerr))
		return nil, fmt.Errorf(C.GoString(cerr))
	}

	return convertCBytesToPrivateKey(out, length)
}

func DeriveChildPkUnhardened(schemeType SchemeMPLType, pk *G1Element, index int) (*G1Element, error) {
	buf := C.CBytes(pk[:])
	defer C.free(buf)

	var out *C.uchar
	var length C.int
	if cerr := C.bls_SchemeMPL_derive_child_pk_unhardened(C.size_t(schemeType), (*C.char)(buf), C.int(index), &out, &length); cerr != nil {
		defer C.free(unsafe.Pointer(cerr))
		return nil, fmt.Errorf(C.GoString(cerr))
	}

	return convertCBytesToG1Element(out, length)
}

func AggregateSignatures(schemeType SchemeMPLType, signatures ...*G2Element) (*G2Element, error) {
	csigs := make([]*C.char, 0, len(signatures))
	defer func() {
		for _, csig := range csigs {
			C.free(unsafe.Pointer(csig))
		}
	}()
	for _, signature := range signatures {
		csigs = append(csigs, (*C.char)(C.CBytes(signature[:])))
	}

	var out *C.uchar
	var length C.int
	if cerr := C.bls_SchemeMPL_aggregate(C.size_t(schemeType), &csigs[0], C.size_t(len(signatures)), &out, &length); cerr != nil {
		defer C.free(unsafe.Pointer(cerr))
		return nil, fmt.Errorf(C.GoString(cerr))
	}

	return convertCBytesToG2Element(out, length)
}

func Sign(schemeType SchemeMPLType, sk *PrivateKey, data []byte) (*G2Element, error) {
	bufSk := C.CBytes(sk[:])
	defer C.free(bufSk)

	bufMsg := C.CBytes(data)
	defer C.free(bufMsg)

	var out *C.uchar
	var length C.int
	if cerr := C.bls_SchemeMPL_sign(C.size_t(schemeType), (*C.char)(bufSk), (*C.char)(bufMsg), C.size_t(len(data)), &out, &length); cerr != nil {
		defer C.free(unsafe.Pointer(cerr))
		return nil, fmt.Errorf(C.GoString(cerr))
	}

	return convertCBytesToG2Element(out, length)
}

func Verify(schemeType SchemeMPLType, pk *G1Element, data []byte, signature *G2Element) (bool, error) {
	bufPk := C.CBytes(pk[:])
	defer C.free(bufPk)

	bufSig := C.CBytes(signature[:])
	defer C.free(bufSig)

	bufData := C.CBytes(data)
	defer C.free(bufData)

	var ok C.int

	if cerr := C.bls_SchemeMPL_verify(C.size_t(schemeType), (*C.char)(bufPk), (*C.char)(bufData), C.size_t(len(data)), (*C.char)(bufSig), &ok); cerr != nil {
		defer C.free(unsafe.Pointer(cerr))
		return false, fmt.Errorf(C.GoString(cerr))
	}

	return int(ok) > 0, nil
}

func AggregateVerify(schemeType SchemeMPLType, pks []*G1Element, datas [][]byte, signature *G2Element) (bool, error) {
	if len(pks) != len(datas) {
		return false, fmt.Errorf("number of pks not matches that of messages")
	}

	// signature
	bufSig := C.CBytes(signature[:])
	defer C.free(bufSig)

	var cerr *C.char
	var ok C.int

	if len(pks) == 0 {
		cerr = C.bls_SchemeMPL_aggregate_verify(C.size_t(schemeType), C.size_t(len(pks)), (**C.char)(nil), (**C.char)(nil), (*C.size_t)(nil), (*C.char)(bufSig), &ok)
	} else {
		// public keys
		cpks := make([]*C.char, 0, len(pks))
		defer func() {
			for _, cpk := range cpks {
				C.free(unsafe.Pointer(cpk))
			}
		}()
		for _, pk := range pks {
			cpks = append(cpks, (*C.char)(C.CBytes(pk[:])))
		}

		// messages
		msgs := make([]*C.char, 0, len(datas))
		lens := make([]C.size_t, 0, len(datas))
		defer func() {
			for _, msg := range msgs {
				C.free(unsafe.Pointer(msg))
			}
		}()
		for _, data := range datas {
			msgs = append(msgs, (*C.char)(C.CBytes(data)))
			lens = append(lens, C.size_t(len(data)))
		}

		cerr = C.bls_SchemeMPL_aggregate_verify(C.size_t(schemeType), C.size_t(len(pks)), &cpks[0], &msgs[0], &lens[0], (*C.char)(bufSig), &ok)
	}
	if cerr != nil {
		defer C.free(unsafe.Pointer(cerr))
		return false, fmt.Errorf(C.GoString(cerr))
	}

	return int(ok) > 0, nil
}

//===============BasicSchemeMPL===============

type BasicSchemeMPL struct{}

func NewBasicSchemeMPL() *BasicSchemeMPL {
	return &BasicSchemeMPL{}
}

// SkToG1 return PublicKey
func (s *BasicSchemeMPL) SkToG1(sk *PrivateKey) (*G1Element, error) {
	return SkToG1(SchemeMPLBasic, sk)
}

func (s *BasicSchemeMPL) KeyGen(seed []byte) (*PrivateKey, error) {
	return KeyGen(SchemeMPLBasic, seed)
}

func (s *BasicSchemeMPL) DeriveChildSk(sk *PrivateKey, index int) (*PrivateKey, error) {
	return DeriveChildSk(SchemeMPLBasic, false, sk, index)
}

func (s *BasicSchemeMPL) DeriveChildSkUnhardened(sk *PrivateKey, index int) (*PrivateKey, error) {
	return DeriveChildSk(SchemeMPLBasic, true, sk, index)
}

func (s *BasicSchemeMPL) DeriveChildPkUnhardened(pk *G1Element, index int) (*G1Element, error) {
	return DeriveChildPkUnhardened(SchemeMPLBasic, pk, index)
}

func (s *BasicSchemeMPL) Aggregate(signatures ...*G2Element) (*G2Element, error) {
	return AggregateSignatures(SchemeMPLBasic, signatures...)
}

func (s *BasicSchemeMPL) Sign(sk *PrivateKey, data []byte) (*G2Element, error) {
	return Sign(SchemeMPLBasic, sk, data)
}

func (s *BasicSchemeMPL) Verify(pk *G1Element, data []byte, signature *G2Element) (bool, error) {
	return Verify(SchemeMPLBasic, pk, data, signature)
}

func (s *BasicSchemeMPL) AggregateVerify(pks []*G1Element, datas [][]byte, signature *G2Element) (bool, error) {
	return AggregateVerify(SchemeMPLBasic, pks, datas, signature)
}

//===============AugSchemeMPL===============

type AugSchemeMPL struct{}

func NewAugSchemeMPL() *AugSchemeMPL {
	return &AugSchemeMPL{}
}

func (s *AugSchemeMPL) SkToG1(sk *PrivateKey) (*G1Element, error) {
	return SkToG1(SchemeMPLAug, sk)
}

func (s *AugSchemeMPL) KeyGen(seed []byte) (*PrivateKey, error) {
	return KeyGen(SchemeMPLAug, seed)
}

func (s *AugSchemeMPL) DeriveChildSk(sk *PrivateKey, index int) (*PrivateKey, error) {
	return DeriveChildSk(SchemeMPLAug, false, sk, index)
}

func (s *AugSchemeMPL) DeriveChildSkUnhardened(sk *PrivateKey, index int) (*PrivateKey, error) {
	return DeriveChildSk(SchemeMPLAug, true, sk, index)
}

func (s *AugSchemeMPL) DeriveChildPkUnhardened(pk *G1Element, index int) (*G1Element, error) {
	return DeriveChildPkUnhardened(SchemeMPLAug, pk, index)
}

func (s *AugSchemeMPL) Aggregate(signatures ...*G2Element) (*G2Element, error) {
	return AggregateSignatures(SchemeMPLAug, signatures...)
}

func (s *AugSchemeMPL) Sign(sk *PrivateKey, data []byte) (*G2Element, error) {
	return Sign(SchemeMPLAug, sk, data)
}

func (s *AugSchemeMPL) Verify(pk *G1Element, data []byte, signature *G2Element) (bool, error) {
	return Verify(SchemeMPLAug, pk, data, signature)
}

func (s *AugSchemeMPL) AggregateVerify(pks []*G1Element, datas [][]byte, signature *G2Element) (bool, error) {
	return AggregateVerify(SchemeMPLAug, pks, datas, signature)
}

func (s *AugSchemeMPL) SignPrepend(sk *PrivateKey, data []byte, pk *G1Element) (*G2Element, error) {
	bufPk := C.CBytes(pk[:])
	defer C.free(bufPk)

	bufSk := C.CBytes(sk[:])
	defer C.free(bufSk)

	bufData := C.CBytes(data)
	defer C.free(bufData)
	// TODO: test 0 data

	var out *C.uchar
	var length C.int
	if cerr := C.bls_AugSchemeMPL_sign_prepend((*C.char)(bufSk), (*C.char)(bufPk), (*C.char)(bufData), C.size_t(len(data)), &out, &length); cerr != nil {
		defer C.free(unsafe.Pointer(cerr))
		return nil, fmt.Errorf(C.GoString(cerr))
	}

	return convertCBytesToG2Element(out, length)
}

//===============PopSchemeMPL===============

type PopSchemeMPL struct{}

func NewPopSchemeMPL() *PopSchemeMPL {
	return &PopSchemeMPL{}
}

func (s *PopSchemeMPL) SkToG1(sk *PrivateKey) (*G1Element, error) {
	return SkToG1(SchemeMPLPop, sk)
}

func (s *PopSchemeMPL) KeyGen(seed []byte) (*PrivateKey, error) {
	return KeyGen(SchemeMPLPop, seed)
}

func (s *PopSchemeMPL) DeriveChildSk(sk *PrivateKey, index int) (*PrivateKey, error) {
	return DeriveChildSk(SchemeMPLPop, false, sk, index)
}

func (s *PopSchemeMPL) DeriveChildSkUnhardened(sk *PrivateKey, index int) (*PrivateKey, error) {
	return DeriveChildSk(SchemeMPLPop, true, sk, index)
}

func (s *PopSchemeMPL) DeriveChildPkUnhardened(pk *G1Element, index int) (*G1Element, error) {
	return DeriveChildPkUnhardened(SchemeMPLPop, pk, index)
}

func (s *PopSchemeMPL) Aggregate(signatures ...*G2Element) (*G2Element, error) {
	return AggregateSignatures(SchemeMPLPop, signatures...)
}

func (s *PopSchemeMPL) Sign(sk *PrivateKey, data []byte) (*G2Element, error) {
	return Sign(SchemeMPLPop, sk, data)
}

func (s *PopSchemeMPL) Verify(pk *G1Element, data []byte, signature *G2Element) (bool, error) {
	return Verify(SchemeMPLPop, pk, data, signature)
}

func (s *PopSchemeMPL) AggregateVerify(pks []*G1Element, datas [][]byte, signature *G2Element) (bool, error) {
	return AggregateVerify(SchemeMPLPop, pks, datas, signature)
}

func (s *PopSchemeMPL) PopProve(sk *PrivateKey) (*G2Element, error) {
	bufSk := C.CBytes(sk[:])
	defer C.free(bufSk)

	var out *C.uchar
	var length C.int
	if cerr := C.bls_PopSchemeMPL_pop_prove((*C.char)(bufSk), &out, &length); cerr != nil {
		defer C.free(unsafe.Pointer(cerr))
		return nil, fmt.Errorf(C.GoString(cerr))
	}

	return convertCBytesToG2Element(out, length)
}

func (s *PopSchemeMPL) PopVerify(pk *G1Element, signature *G2Element) (bool, error) {
	bufPk := C.CBytes(pk[:])
	defer C.free(bufPk)
	bufSig := C.CBytes(signature[:])
	defer C.free(bufSig)

	var ok C.int
	if cerr := C.bls_PopSchemeMPL_pop_verify((*C.char)(bufPk), (*C.char)(bufSig), &ok); cerr != nil {
		defer C.free(unsafe.Pointer(cerr))
		return false, fmt.Errorf(C.GoString(cerr))
	}

	return int(ok) > 0, nil
}

func (s *PopSchemeMPL) FastAggregateVerify(pks []*G1Element, data []byte, signature *G2Element) (bool, error) {
	cpks := make([]*C.char, 0, len(pks))
	defer func() {
		for _, cpk := range cpks {
			C.free(unsafe.Pointer(cpk))
		}
	}()
	for _, pk := range pks {
		cpks = append(cpks, (*C.char)(C.CBytes(pk[:])))
	}

	buf := C.CBytes(data)
	defer C.free(buf)
	bufSig := C.CBytes(signature[:])
	defer C.free(bufSig)

	var ok C.int
	if cerr := C.bls_PopSchemeMPL_fast_aggregate_verify(&cpks[0], C.size_t(len(pks)), (*C.char)(buf), C.size_t(len(data)), (*C.char)(bufSig), &ok); cerr != nil {
		defer C.free(unsafe.Pointer(cerr))
		return false, fmt.Errorf(C.GoString(cerr))
	}

	return int(ok) > 0, nil
}
