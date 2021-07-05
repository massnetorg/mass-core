package forks

import (
	"fmt"

	"github.com/massnetorg/mass-core/consensus"
	"github.com/massnetorg/mass-core/massutil"
	"github.com/massnetorg/mass-core/massutil/safetype"
	"github.com/massnetorg/mass-core/wire"
)

type StakingNode interface {
	GetValue() int64
	GetWeight() *safetype.Uint128
}

type StakingTx interface {
	GetBlockHeight() uint64
	GetFrozenPeriod() uint64
}

func CalcTotalStakingWeight(blockHeight uint64, stakingNodes ...StakingNode) (*safetype.Uint128, error) {
	totalWeight := safetype.NewUint128()
	var err error
	for _, node := range stakingNodes {
		if blockHeight < consensus.MASSIP0001Height {
			// by value
			totalWeight, err = totalWeight.AddInt(node.GetValue())
		} else {
			// by weight
			totalWeight, err = totalWeight.Add(node.GetWeight())
		}
		if err != nil {
			return nil, err
		}
	}
	return totalWeight, nil
}

func CalcStakingNodeWeight(blockHeight uint64, stakingNode StakingNode) (*safetype.Uint128, error) {
	if blockHeight < consensus.MASSIP0001Height {
		return safetype.NewUint128FromInt(stakingNode.GetValue())
	}
	return stakingNode.GetWeight(), nil
}

func CalcEffectiveStakingPeriod(blockHeight uint64, stakingTx StakingTx) (period uint64) {
	if blockHeight < consensus.MASSIP0001Height {
		tmp := stakingTx.GetBlockHeight() + stakingTx.GetFrozenPeriod() + 1
		if tmp >= blockHeight {
			period = tmp - blockHeight
		}
	} else {
		period = stakingTx.GetFrozenPeriod()
		if period > consensus.MASSIP0001MaxValidPeriod {
			period = consensus.MASSIP0001MaxValidPeriod
		}
	}
	return
}

func SortStakingNodesByWeight(blockHeight uint64) bool {
	return blockHeight >= consensus.MASSIP0001Height
}

// 1. Disable old binding, enfore new binding.
//
// 2. Allow set coinbase related to pool_pk.
//
// 3. Disallow minting without binding.
//
// 4. New reward logic.
//
// 5. Both MASS and Chia miner available.
func EnforceMASSIP0002(blockHeight uint64) bool {
	return blockHeight >= consensus.MASSIP0002Height
}

// 1. Disable old binding, enfore new binding.
//
// 2. Allow set coinbase related to pool_pk.
//
// 3. Base minting reward (no binding reward).
//
// 4. Only MASS miner available.
func EnforceMASSIP0002WarmUp(blockHeight uint64) bool {
	return blockHeight >= consensus.MASSIP0002WarmUpHeight
}

func GetRequiredBinding(nextHeight, plotSize uint64, massBitlength int, networkBinding massutil.Amount) (massutil.Amount, error) {
	if !EnforceMASSIP0002WarmUp(nextHeight) {
		price, ok := bindingPriceSinceGenesis[massBitlength]
		if !ok {
			return massutil.ZeroAmount(), fmt.Errorf("invalid mass bitlength %d", massBitlength)
		}
		return price, nil
	}

	if plotSize == 0 {
		return massutil.ZeroAmount(), fmt.Errorf("unexpected zero plot size")
	}

	n := plotSize >> 35 // number of 32-GiB
	if n == 0 {
		n = 1
	}
	for _, netPrice := range bindingPriceSinceMASSIP0002 {
		if networkBinding.Cmp(netPrice.AccumulativeUpperBound) <= 0 {
			u, err := netPrice.PricePer32G.Value().MulInt(int64(n))
			if err != nil {
				return massutil.ZeroAmount(), err
			}
			return massutil.NewAmount(u)
		}
	}

	// not found in pre calculated price
	var err error
	acc := bindingPriceSinceMASSIP0002[len(bindingPriceSinceMASSIP0002)-1].AccumulativeUpperBound
	for i := len(bindingPriceSinceMASSIP0002) + 1; ; i++ {
		massPerPB, intervalTotal := calcIntervalRequired(i)
		acc, err = acc.Add(newAmountFromMASS(intervalTotal))
		if err != nil {
			return massutil.ZeroAmount(), fmt.Errorf("failed calculating price: %v", err)
		}

		if networkBinding.Cmp(acc) <= 0 {
			pricePerPB := newAmountFromMASS(massPerPB)
			u, err := pricePerPB.Value().DivInt(NumberOf32GOnePB)
			if err != nil {
				return massutil.ZeroAmount(), err
			}
			pricePer32G, err := massutil.NewAmount(u)
			if err != nil {
				return massutil.ZeroAmount(), err
			}

			price, err := pricePer32G.Value().MulInt(int64(n))
			if err != nil {
				return massutil.ZeroAmount(), err
			}
			return massutil.NewAmount(price)
		}
	}

}

func GetBlockVersion(height uint64) uint64 {
	if EnforceMASSIP0002WarmUp(height) {
		return wire.BlockVersionV2
	} else {
		return wire.BlockVersionV1
	}
}
