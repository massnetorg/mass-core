package forks

import (
	"encoding/hex"
	"math/big"

	"github.com/massnetorg/mass-core/consensus"
	"github.com/massnetorg/mass-core/massutil"
	"github.com/massnetorg/mass-core/massutil/safetype"
	"github.com/massnetorg/mass-core/wire"
)

const (
	NumberOf32GOnePB = (1 << 50) >> 35
)

type GenesisBindingPrices map[int]massutil.Amount

type NetworkBindingPrice struct {
	AccumulativeUpperBound massutil.Amount
	PricePer32G            massutil.Amount
}

var (
	bindingPriceSinceGenesis    = make(GenesisBindingPrices)
	bindingPriceSinceMASSIP0002 []*NetworkBindingPrice
)

func init() {
	// since genesis
	for bitlength, required := range map[int]uint64{
		24: 614_400,        // 0.006144
		26: 2_662_400,      // 0.026624,
		28: 11_200_000,     // 0.112,
		30: 48_000_000,     // 0.48,
		32: 204_800_000,    // 2.048,
		34: 870_400_000,    // 8.704,
		36: 3_686_400_000,  // 36.864,
		38: 15_200_000_000, // 152,
		40: 64_000_000_000, // 640,
	} {
		amt, err := massutil.NewAmountFromUint(required)
		if err != nil {
			panic(err)
		}
		bindingPriceSinceGenesis[bitlength] = amt
	}

	// since mass ip2
	massPerPB, intervalTotal := calcIntervalRequired(3)
	bindingPriceSinceMASSIP0002 = []*NetworkBindingPrice{
		{newAmountFromMASS(intervalTotal), calcPricePer32G(massPerPB)},
		{newAmountFromMASS(intervalTotal * 2), calcPricePer32G(massPerPB)},
	}
	var err error
	acc := bindingPriceSinceMASSIP0002[1].AccumulativeUpperBound
	for i := 3; i <= 30; i++ {
		massPerPB, intervalTotal := calcIntervalRequired(i)
		if acc, err = acc.Add(newAmountFromMASS(intervalTotal)); err != nil {
			panic(err)
		}
		bindingPriceSinceMASSIP0002 = append(bindingPriceSinceMASSIP0002, &NetworkBindingPrice{
			AccumulativeUpperBound: acc,
			PricePer32G:            calcPricePer32G(massPerPB),
		})
	}
}

func mustDecodeHash(str string) wire.Hash {
	h, err := wire.NewHashFromStr(str)
	if err != nil {
		panic(err)
	}
	return *h
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

func calcIntervalRequired(i int) (massPerPB, total uint64) {
	return uint64(5_000_000 / (i * 100)), uint64(5_000_000 / i) // 100PB
}

func newAmountFromMASS(i uint64) massutil.Amount {
	u := safetype.NewUint128FromUint(i)
	u, err := u.MulInt(int64(consensus.MaxwellPerMass))
	if err != nil {
		panic(err)
	}
	amt, err := massutil.NewAmount(u)
	if err != nil {
		panic(err)
	}
	return amt
}

func newAmountFromMaxwell(i uint64) massutil.Amount {
	amt, err := massutil.NewAmountFromUint(i)
	if err != nil {
		panic(err)
	}
	return amt
}

func calcPricePer32G(massPerPB uint64) massutil.Amount {
	m := newAmountFromMASS(massPerPB)
	u, err := m.Value().DivInt(NumberOf32GOnePB)
	if err != nil {
		panic(err)
	}
	price, err := massutil.NewAmount(u)
	if err != nil {
		panic(err)
	}
	return price
}
