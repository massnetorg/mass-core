package state

import "encoding/binary"

// TODO:
type BindingInfo struct {
	Amount int64
}

func DecodeBindingInfo(buf []byte) *BindingInfo {
	if len(buf) == 0 {
		return &BindingInfo{}
	}

	return &BindingInfo{
		Amount: int64(binary.BigEndian.Uint64(buf)),
	}
}

func EncodeBindingInfo(info *BindingInfo) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(info.Amount))
	return buf[:]
}
