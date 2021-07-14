package massutil

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/massnetorg/mass-core/config"
	"github.com/massnetorg/mass-core/poc"
	"github.com/massnetorg/mass-core/poc/chiapos"
	"github.com/massnetorg/mass-core/poc/pocutil"
	"github.com/massnetorg/mass-core/pocec"
)

const bindingListFileMaxByteSize = 100 * poc.MiB

type BindingList struct {
	Plots        []BindingPlot `json:"plots"`
	TotalCount   uint64        `json:"total_count"`
	DefaultCount uint64        `json:"default_count"`
	ChiaCount    uint64        `json:"chia_count"`
}

func (list *BindingList) RemoveDuplicate() *BindingList {
	var newPlots = make([]BindingPlot, 0, len(list.Plots))
	var duplicate = make(map[string]bool, len(list.Plots))
	var counts = make(map[uint8]uint64, 2)
	for i, plot := range list.Plots {
		if duplicate[plot.String()] || !poc.IsValidProofType(poc.ProofType(plot.Type)) {
			continue
		}
		newPlots = append(newPlots, list.Plots[i])
		duplicate[plot.String()] = true
		counts[plot.Type] += 1
	}
	list.Plots = newPlots
	list.DefaultCount = counts[uint8(poc.ProofTypeDefault)]
	list.ChiaCount = counts[uint8(poc.ProofTypeChia)]
	list.TotalCount = list.DefaultCount + list.ChiaCount
	return list
}

func (list *BindingList) WriteToFile(filename string) error {
	list = list.RemoveDuplicate()
	data, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filename, data, 0644)
}

type BindingPlot struct {
	Target string `json:"target"`
	Type   uint8  `json:"type"`
	Size   uint8  `json:"size"`
}

func (plot BindingPlot) Equals(target BindingPlot) bool {
	return plot.Target == target.Target &&
		plot.Type == target.Type &&
		plot.Size == target.Size
}

func (plot BindingPlot) String() string {
	return fmt.Sprintf("%s/%d/%d", plot.Target, plot.Type, plot.Size)
}

func NewBindingListFromFile(filename string) (*BindingList, error) {
	fi, err := os.Stat(filename)
	if err != nil {
		return nil, err
	}
	if fi.Size() > bindingListFileMaxByteSize {
		return nil, errors.New("binding list file is larger than limit")
	}
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	list := &BindingList{}
	if err = json.Unmarshal(data, list); err != nil {
		return nil, err
	}
	return list, nil
}

func GetMassDBBindingTarget(pubKey *pocec.PublicKey, bitLength int) (string, error) {
	return GetBindingTarget(pubKey.SerializeCompressed(), poc.ProofTypeDefault, bitLength)
}

func GetChiaPlotBindingTarget(plotID pocutil.Hash, k int) (string, error) {
	return GetBindingTarget(plotID.Bytes(), poc.ProofTypeChia, k)
}

// GetBindingTarget returns the binding target for plots.
// For native MassDB, pub should be the SerializeCompressed PublicKey.
// For Chia Plot, pub should be the 32-byte PlotID.
func GetBindingTarget(pub []byte, proofType poc.ProofType, bitLength int) (string, error) {
	hash := append(Hash160(pub), byte(proofType), byte(bitLength))
	target, err := NewAddressBindingTarget(hash, &config.ChainParams)
	if err != nil {
		return "", err
	}
	return target.EncodeAddress(), nil
}

// MassDB info for native plot file.
type MassDBInfoV1 struct {
	PublicKey     *pocec.PublicKey
	PublicKeyHash pocutil.Hash
	BitLength     int
	Plotted       bool
}

func NewMassDBInfoV1FromFile(plotFile string) (*MassDBInfoV1, error) {
	const (
		DBVersion     = 1
		DBFileCodeStr = "52A7AD74C4929DEC7B5C8D46CC3BAFA81FC96129283B3A6923CD12F41A30B3AC"
		PosFileCode   = 0
		PosVersion    = 32
		PosBitLength  = 40
		PosCheckpoint = 42
		PosPubKeyHash = 50
		PosPubKey     = 82
		LenMetaInfo   = 4096
	)

	f, err := os.OpenFile(plotFile, os.O_RDONLY, 0666)
	if nil != err {
		return nil, err
	}
	defer f.Close()

	// read meta info
	var (
		b1  [1]byte
		b8  [8]byte
		b32 [32]byte
		b33 [33]byte
	)

	var fileHeaderBytes [LenMetaInfo]byte
	if _, err := f.ReadAt(fileHeaderBytes[:], 0); err != nil {
		return nil, errors.New("massdb file size is smaller than expected")
	}

	// Check fileCode
	copy(b32[:], fileHeaderBytes[PosFileCode:])
	if hex.EncodeToString(b32[:]) != DBFileCodeStr {
		return nil, errors.New("massdb file code is not as expected")
	}

	// Check dbVersion
	copy(b8[:], fileHeaderBytes[PosVersion:])
	if ver := binary.LittleEndian.Uint64(b8[:]); ver != DBVersion {
		return nil, errors.New("unknown massdb version")
	}

	// Get BitLength
	copy(b1[:], fileHeaderBytes[PosBitLength:])
	bl := int(b1[0])

	// Get Checkpoint
	copy(b8[:], fileHeaderBytes[PosCheckpoint:])
	checkpoint := pocutil.PoCValue(binary.LittleEndian.Uint64(b8[:]))

	// Get PubKeyHash
	var pkHash pocutil.Hash
	copy(pkHash[:], fileHeaderBytes[PosPubKeyHash:])

	// Get PubKey
	copy(b33[:], fileHeaderBytes[PosPubKey:])
	pk, err := pocec.ParsePubKey(b33[:], pocec.S256())
	if err != nil {
		return nil, err
	}

	// check pubKey with pubKeyHash
	if pkHash != pocutil.PubKeyHash(pk) {
		return nil, errors.New("public_key_hash is not matched with public_key")
	}

	return &MassDBInfoV1{
		PublicKey:     pk,
		PublicKeyHash: pkHash,
		BitLength:     bl,
		Plotted:       checkpoint >= (1 << uint(bl-1)),
	}, nil
}

// MassDB info for chia plot file.
type MassDBInfoV2 struct {
	PoolPublicKey   *chiapos.G1Element
	FarmerPublicKey *chiapos.G1Element
	PlotPublicKey   *chiapos.G1Element
	PlotID          pocutil.Hash
	K               int
}

func NewMassDBInfoV2FromFile(plotFile string) (*MassDBInfoV2, error) {
	dp, err := chiapos.NewDiskProver(plotFile, true)
	if err != nil {
		return nil, err
	}
	defer dp.Close()

	plotInfo := dp.PlotInfo()

	return &MassDBInfoV2{
		PoolPublicKey:   plotInfo.PoolPublicKey,
		FarmerPublicKey: plotInfo.FarmerPublicKey,
		PlotPublicKey:   plotInfo.PlotPublicKey,
		PlotID:          dp.ID(),
		K:               int(dp.Size()),
	}, nil
}
