package poc_test

import (
	crand "crypto/rand"
	"fmt"
	"math/big"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/massnetorg/mass-core/poc"
	"github.com/massnetorg/mass-core/poc/pocutil"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func TestWinningRate(t *testing.T) {
	var bl = 32
	var defaultProofCount, chiaProofCount = 400 * poc.QualityConstantMASSValidity, 100
	var round = 10000
	var defaultWinRound int
	for i := 0; i < round; i++ {
		if randomDefaultQualitiesV2(int(defaultProofCount), bl).Max().Cmp(
			randomChiaQualities(chiaProofCount, bl).Max()) >= 0 {
			defaultWinRound++
		}
	}
	fmt.Println("total_round", round)
	fmt.Println("default_proof_wining", defaultWinRound)
	fmt.Println("chia_proof_wining", round-defaultWinRound)
}

func TestUnitWinningRate(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	var bl = 32
	var round = 100000
	var defaultWinRound, chiaWinRound int
	var target = estimatedTarget(poc.ProofTypeChia, bl, 1)
	defaultQualities := randomDefaultQualitiesV2(round, bl).Raw()
	chiaQualities := randomChiaQualities(round, bl).Raw()
	for i := 0; i < round; i++ {
		if defaultQualities[i].Cmp(chiaQualities[i]) >= 0 {
			if defaultQualities[i].Cmp(target) >= 0 {
				defaultWinRound++
			}
		} else if chiaQualities[i].Cmp(target) >= 0 {
			chiaWinRound++
		}
	}
	fmt.Println("total_round", round)
	fmt.Println("default_proof_wining", defaultWinRound)
	fmt.Println("chia_proof_wining", chiaWinRound)
}

func TestMASSIP0002ForkQuality(t *testing.T) {
	var bl = 32
	var defaultV1QualityCount, defaultV2QualityCount = 51200, 100
	var round = 100
	var v1WinRound int
	for i := 0; i < round; i++ {
		if randomDefaultQualitiesV1(defaultV1QualityCount, bl).Max().Cmp(
			randomDefaultQualitiesV2(defaultV2QualityCount, bl).Max()) >= 0 {
			v1WinRound++
		}
	}
	fmt.Println("total_round", round)
	fmt.Println("default_proof_wining", v1WinRound)
	fmt.Println("chia_proof_wining", round-v1WinRound)
}

type QualitySlice struct {
	raw    []*big.Int
	data   []*big.Int
	sorted bool
}

func NewQualitySlice(qualities []*big.Int) *QualitySlice {
	return &QualitySlice{
		raw:  qualities,
		data: qualities,
	}
}

func (qs *QualitySlice) Len() int {
	return len(qs.data)
}

func (qs *QualitySlice) Raw() []*big.Int {
	return qs.raw
}

func (qs *QualitySlice) Sorted() []*big.Int {
	qs.sort()
	return qs.data
}

func (qs *QualitySlice) Max() *big.Int {
	qs.sort()
	var max *big.Int
	if len(qs.data) > 0 {
		max = qs.data[len(qs.data)-1]
	} else {
		max = big.NewInt(-1)
	}
	return max
}

func (qs *QualitySlice) Min() *big.Int {
	qs.sort()
	var min *big.Int
	if len(qs.data) > 0 {
		min = qs.data[0]
	}
	return min
}

func (qs *QualitySlice) SatisfyTarget(target *big.Int) *QualitySlice {
	qs.sort()
	var idx = -1
	for i := range qs.data {
		if qs.data[i].Cmp(target) >= 0 {
			idx = i
			break
		}
	}
	var subQualities []*big.Int
	if idx > -1 {
		subQualities = qs.data[idx:]
	}
	return NewQualitySlice(subQualities)
}

func (qs *QualitySlice) sort() {
	if qs.sorted {
		return
	}
	sort.SliceStable(qs.data, func(i, j int) bool {
		return qs.data[i].Cmp(qs.data[j]) < 0
	})
	qs.sorted = true
}

func randomDefaultQualitiesV1(n, bitLength int) *QualitySlice {
	var qualities []*big.Int
	var h = randHash()
	var q1 = poc.Q1FactorDefault(bitLength)
	for i := 0; i < n; i++ {
		h = pocutil.SHA256(h[:])
		qualities = append(qualities, poc.GetQuality(q1, h))
	}
	return NewQualitySlice(qualities)
}

func randomDefaultQualitiesV2(n, bitLength int) *QualitySlice {
	var qualities []*big.Int
	var h = randHash()
	var q1 = poc.Q1FactorDefault(bitLength)
	q1.Mul(q1, big.NewFloat(poc.QualityConstantMASSIP0002))
	for i := 0; i < n; i++ {
		h = pocutil.SHA256(h[:])
		qualities = append(qualities, poc.GetQuality(q1, h))
	}
	return NewQualitySlice(qualities)
}

func randomChiaQualities(n, k int) *QualitySlice {
	var qualities []*big.Int
	var h = randHash()
	var q1 = poc.Q1FactorChia(uint8(k))
	for i := 0; i < n; i++ {
		h = pocutil.SHA256(h[:])
		qualities = append(qualities, poc.GetQuality(q1, h))
	}
	return NewQualitySlice(qualities)
}

func randHash() pocutil.Hash {
	var h pocutil.Hash
	crand.Read(h[:])
	return h
}

func estimatedTarget(proofType poc.ProofType, bitLength, proofCount int) *big.Int {
	const GiB = 1024 * 1024 * 1024
	var qualityGiB = big.NewInt(2e12 * 50)
	plotGiBSize := poc.PlotSize(proofType, bitLength) / GiB
	target := big.NewInt(int64(plotGiBSize))
	target.Mul(target, big.NewInt(int64(proofCount)))
	target.Mul(target, qualityGiB)
	return target
}
