package blockchain

import (
	"fmt"

	"github.com/massnetorg/mass-core/config"
	"github.com/massnetorg/mass-core/consensus"
	"github.com/massnetorg/mass-core/consensus/forks"
	"github.com/massnetorg/mass-core/massutil"
	"github.com/massnetorg/mass-core/massutil/safetype"
)

var (
	baseSubsidy                = safetype.NewUint128FromUint(consensus.BaseSubsidy)
	minHalvedSubsidy           = safetype.NewUint128FromUint(consensus.MinHalvedSubsidy)     //0.0625
	minHalvedSubsidyForMASSIP2 = safetype.NewUint128FromUint(consensus.MinHalvedSubsidy * 4) // 0.25

	fakeMASSIP2SubsidyStartHeight = uint64(0)
)

func init() {
	if consensus.MASSIP0002Height > 846720 && consensus.MASSIP0002Height <= 1706880 { // mainnet, period 7
		height := consensus.MASSIP0002Height - 846720   // 846720 is last block of period 6
		height *= 215040                                // 215040 is total blocks in period 5
		height /= 860160                                // 860160 is total blocks in period 7
		fakeMASSIP2SubsidyStartHeight = 201601 + height // 201601 is start block of period 5
	}
}

// CalcBlockSubsidy returns the subsidy amount a block at the provided height
// should have. This is mainly used for determining how much the coinbase for
// newly generated blocks awards as well as validating the coinbase for blocks
// has the expected value.
//
// The subsidy is halved every SubsidyHalvingInterval blocks.  Mathematically
// this is: BaseSubsidy / 2^(height/subsidyHalvingInterval)
//
// At the Target block generation rate for the main network, this is
// approximately every 4 years.
func CalcBlockSubsidy(height uint64, chainParams *config.Params, hasValidBinding, hasStaking bool) (miner, superNode massutil.Amount, err error) {
	if !forks.EnforceMASSIP0002(height) {
		hasGameReward := true
		if forks.EnforceMASSIP0002WarmUp(height) {
			hasValidBinding = false
			hasGameReward = false
		}
		return calcBlockSubsidyBeforeIp2(height, chainParams, hasValidBinding, hasStaking, hasGameReward)
	}

	if !hasValidBinding {
		return massutil.ZeroAmount(), massutil.ZeroAmount(), fmt.Errorf("unexpect no valid binding")
	}
	return calcBlockSubsidy(height, chainParams, hasStaking)
}

func calcBlockSubsidyBeforeIp2(height uint64, chainParams *config.Params, hasValidBinding, hasStaking, hasGameReward bool) (miner, superNode massutil.Amount, err error) {

	subsidy := baseSubsidy
	if chainParams.SubsidyHalvingInterval != 0 {
		subsidy = baseSubsidy.Rsh(calcRshNumBeforeIp2(height))
		if subsidy.Lt(minHalvedSubsidy) {
			subsidy = safetype.NewUint128()
		}
	}

	if subsidy.IsZero() {
		return massutil.ZeroAmount(), massutil.ZeroAmount(), nil
	}

	return allocSubsidyBeforeIp2(subsidy, hasValidBinding, hasStaking, hasGameReward)
}

func calcRshNumBeforeIp2(height uint64) uint {
	t := (height-1)/consensus.SubsidyHalvingInterval + 1
	i := uint(0)
	for {
		t = t >> 1
		if t != 0 {
			i++
		} else {
			return i
		}
	}
}

func allocSubsidyBeforeIp2(subsidy *safetype.Uint128, hasValidBinding, hasStaking, hasGameReward bool) (binding, staking massutil.Amount, err error) {

	temp := safetype.NewUint128()
	miner := safetype.NewUint128()
	superNode := safetype.NewUint128()

	if hasGameReward {
		switch {
		case !hasStaking && !hasValidBinding:
			// miner get 18.75%
			temp, err = subsidy.MulInt(1875)
			if err != nil {
				break
			}
			miner, err = temp.DivInt(10000)
		case !hasStaking && hasValidBinding:
			// miner get 81.25%
			temp, err = subsidy.MulInt(8125)
			if err != nil {
				break
			}
			miner, err = temp.DivInt(10000)
		case hasStaking && !hasValidBinding:
			// miner get 18.75%
			// superNode get 81.25%
			temp, err = subsidy.MulInt(1875)
			if err != nil {
				break
			}
			miner, err = temp.DivInt(10000)
			if err != nil {
				break
			}
			superNode, err = subsidy.Sub(miner)
		default:
			// hasStaking && hasValidBinding
			// miner get 81.25%
			// superNode get 18.75%
			temp, err = subsidy.MulInt(8125)
			if err != nil {
				break
			}
			miner, err = temp.DivInt(10000)
			if err != nil {
				break
			}
			superNode, err = subsidy.Sub(miner)
		}
	} else {
		if miner, err = subsidy.MulInt(1875); err == nil {
			if miner, err = miner.DivInt(10000); err == nil && hasStaking {
				superNode = miner.DeepCopy()
			}
		}
	}
	if err != nil {
		return massutil.ZeroAmount(), massutil.ZeroAmount(), err
	}
	m, err := massutil.NewAmount(miner)
	if err != nil {
		return massutil.ZeroAmount(), massutil.ZeroAmount(), err
	}
	sn, err := massutil.NewAmount(superNode)
	if err != nil {
		return massutil.ZeroAmount(), massutil.ZeroAmount(), err
	}
	return m, sn, nil
}

func calcBlockSubsidy(height uint64, chainParams *config.Params, hasStaking bool) (miner, superNode massutil.Amount, err error) {

	subsidy := baseSubsidy
	if chainParams.SubsidyHalvingInterval != 0 {
		if fakeMASSIP2SubsidyStartHeight != 0 {
			// for mainnet
			if height < consensus.MASSIP0002Height {
				return massutil.ZeroAmount(), massutil.ZeroAmount(), fmt.Errorf("unexpected height in calcBlockSubsidy")
			}
			height = fakeMASSIP2SubsidyStartHeight + height - consensus.MASSIP0002Height
		}
		n := calcRshNumBeforeIp2(height)
		subsidy = baseSubsidy.Rsh(n)
		if subsidy.Lt(minHalvedSubsidyForMASSIP2) {
			subsidy = safetype.NewUint128()
		}
	}

	if subsidy.IsZero() {
		return massutil.ZeroAmount(), massutil.ZeroAmount(), nil
	}

	return allocSubsidy(subsidy, hasStaking)
}

func allocSubsidy(subsidy *safetype.Uint128, hasStaking bool) (binding, staking massutil.Amount, err error) {
	// 0% or 10% of subsidy to staking nodes
	stakingNodes := safetype.NewUint128()
	if hasStaking {
		stakingNodes, err = subsidy.DivInt(10)
		if err != nil {
			return massutil.ZeroAmount(), massutil.ZeroAmount(), err
		}
	}

	// 90% of subsidy to miner
	miner, err := subsidy.Sub(stakingNodes)
	if err == nil && stakingNodes.IsZero() {
		if miner, err = subsidy.MulInt(9); err == nil {
			miner, err = miner.DivInt(10)
		}
	}
	if err != nil {
		return massutil.ZeroAmount(), massutil.ZeroAmount(), err
	}

	if binding, err = massutil.NewAmount(miner); err == nil {
		if staking, err = massutil.NewAmount(stakingNodes); err == nil {
			return binding, staking, nil
		}
	}
	return massutil.ZeroAmount(), massutil.ZeroAmount(), err
}
