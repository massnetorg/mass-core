package blockchain

import (
	"fmt"
	"strings"
	"testing"

	"github.com/massnetorg/mass-core/config"
	"github.com/massnetorg/mass-core/consensus"
	"github.com/massnetorg/mass-core/massutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCalcBlockSubsidy(t *testing.T) {
	amount0 := massutil.ZeroAmount()
	// amount614399, _ := massutil.NewAmountFromInt(614399)
	// amount614400, _ := massutil.NewAmountFromInt(614400)
	amount9600000000, _ := massutil.NewAmountFromInt(9600000000)
	amount19200000000, _ := massutil.NewAmountFromInt(19200000000)
	amount83200000000, err := massutil.NewAmountFromInt(83200000000)
	if err != nil {
		t.Fatalf("failed to new amount 83200000000, %v", err)
	}
	tests := []struct {
		name          string
		height        uint64
		validBinding  bool
		numRank       int
		bitLength     int
		miner         massutil.Amount
		superNode     massutil.Amount
		hasGameReward bool
	}{
		{
			name:          "case 1",
			height:        uint64(13440),
			validBinding:  false,
			numRank:       0,
			bitLength:     24,
			miner:         amount19200000000,
			superNode:     amount0,
			hasGameReward: true,
		},
		{
			name:          "case 2",
			height:        uint64(13441),
			validBinding:  false,
			numRank:       0,
			bitLength:     24,
			miner:         amount9600000000,
			superNode:     amount0,
			hasGameReward: true,
		},
		{
			name:          "case 3",
			height:        uint64(13440),
			validBinding:  false,
			numRank:       10,
			bitLength:     24,
			miner:         amount19200000000,
			superNode:     amount83200000000,
			hasGameReward: true,
		},
		{
			name:          "case 4",
			height:        uint64(13440),
			validBinding:  true,
			numRank:       0,
			bitLength:     24,
			miner:         amount83200000000,
			superNode:     amount0,
			hasGameReward: true,
		},
		{
			name:          "case 5",
			height:        uint64(13440),
			validBinding:  true,
			numRank:       10,
			bitLength:     24,
			miner:         amount83200000000,
			superNode:     amount19200000000,
			hasGameReward: true,
		},
		{
			name:          "case 6",
			height:        uint64(13440),
			validBinding:  false,
			numRank:       10,
			bitLength:     24,
			miner:         amount19200000000,
			superNode:     amount83200000000,
			hasGameReward: true,
		},
		{
			name:          "case 7",
			height:        uint64(13440),
			validBinding:  false,
			numRank:       1,
			bitLength:     24,
			miner:         amount19200000000,
			superNode:     amount19200000000,
			hasGameReward: false,
		},
		{
			name:          "case 8",
			height:        uint64(13440),
			validBinding:  false,
			numRank:       0,
			bitLength:     24,
			miner:         amount19200000000,
			superNode:     amount0,
			hasGameReward: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resMiner, resSuperNode, err := calcBlockSubsidyBeforeIp2(test.height, &config.ChainParams,
				test.validBinding, test.numRank > 0, test.hasGameReward)
			if err != nil {
				t.Errorf("failed to calculate block subsidy, %v", err)
			}
			// t.Logf("result: miner: %v, superNode: %v, expect: miner: %v, superNode: %v", resMiner, resSuperNode, data.miner, data.superNode)
			assert.Equal(t, resMiner.String(), test.miner.String())
			assert.Equal(t, resSuperNode.String(), test.superNode.String())
		})
	}
}

func TestMASSIP2CalcBlockSubsidy(t *testing.T) {

	amount0 := massutil.ZeroAmount()
	amount5760000000, _ := massutil.NewAmountFromInt(5760000000)
	amount2880000000, _ := massutil.NewAmountFromInt(2880000000)
	amount45000000, _ := massutil.NewAmountFromInt(45000000)
	amount5000000, _ := massutil.NewAmountFromInt(5000000)
	amount22500000, _ := massutil.NewAmountFromInt(22500000)
	amount2500000, _ := massutil.NewAmountFromInt(2500000)

	assert.True(t, fakeMASSIP2SubsidyStartHeight == uint64(341121), fakeMASSIP2SubsidyStartHeight)

	tests := []struct {
		name      string
		height    uint64
		numRank   int
		miner     massutil.Amount
		superNode massutil.Amount
		expectErr string
	}{
		{
			name:      "fork start - 1",
			height:    uint64(consensus.MASSIP0002Height - 1),
			expectErr: "unexpected height in calcBlockSubsidy",
		},
		{
			name:      "fork start",
			height:    uint64(consensus.MASSIP0002Height),
			numRank:   0,
			miner:     amount5760000000, // 90%
			superNode: amount0,          // 0%
		},
		{
			name:      "fake period 5 end",
			height:    uint64(consensus.MASSIP0002Height + 416640 - fakeMASSIP2SubsidyStartHeight), // 416640 is last block of period 5
			numRank:   0,
			miner:     amount5760000000, // 90%
			superNode: amount0,          // 0%
		},
		{
			name:      "after fake period 5 end",
			height:    uint64(consensus.MASSIP0002Height + 416640 - fakeMASSIP2SubsidyStartHeight + 1),
			numRank:   0,
			miner:     amount2880000000, // 90%
			superNode: amount0,          // 0%
		},
		{
			name:      "fake period 12 end with staking",
			height:    uint64(consensus.MASSIP0002Height + 55036800 - fakeMASSIP2SubsidyStartHeight), // 55036800 is last block of period 12
			numRank:   1,
			miner:     amount45000000, // 90%
			superNode: amount5000000,  // 10%
		},
		{
			name:      "fake period 13 end",
			height:    uint64(consensus.MASSIP0002Height + 110087040 - fakeMASSIP2SubsidyStartHeight), // 110087040 is last block of period 13
			numRank:   0,
			miner:     amount22500000, // 90%
			superNode: amount0,        // 0%
		},
		{
			name:      "fake period 13 end with staking",
			height:    uint64(consensus.MASSIP0002Height + 110087040 - fakeMASSIP2SubsidyStartHeight),
			numRank:   1,
			miner:     amount22500000, // 90%
			superNode: amount2500000,  // 10%
		},
		{
			name:      "after fake period 13 end",
			height:    uint64(consensus.MASSIP0002Height + 110087040 - fakeMASSIP2SubsidyStartHeight + 1),
			numRank:   0,
			miner:     amount0,
			superNode: amount0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resMiner, resSuperNode, err := calcBlockSubsidy(test.height, &config.ChainParams, test.numRank > 0)
			if test.expectErr != "" {
				assert.NotNil(t, err)
				assert.True(t, strings.Contains(err.Error(), test.expectErr))
				return
			} else if err != nil {
				t.Fatalf("failed to calculate block subsidy, %v", err)
			}
			assert.Equal(t, test.miner.String(), resMiner.String())
			assert.Equal(t, test.superNode.String(), resSuperNode.String())
		})
	}
}

func ExampleCalcBlockSubsidy(t *testing.T) {
	for i := uint64(1404798); i <= 1404802; i++ {
		miner, node, err := CalcBlockSubsidy(i, &config.ChainParams, true, true)
		require.NoError(t, err)
		fmt.Println(i, miner, node)
	}
	fmt.Println("-------------------")
	for i := uint64(1480318); i <= 1480322; i++ {
		miner, node, err := CalcBlockSubsidy(i, &config.ChainParams, true, true)
		require.NoError(t, err)
		fmt.Println(i, miner, node)
	}
	fmt.Println("-------------------")
	for i := uint64(56100478); i <= 56100482; i++ {
		miner, node, err := CalcBlockSubsidy(i, &config.ChainParams, true, true)
		require.NoError(t, err)
		fmt.Println(i, miner, node)
	}
	fmt.Println("-------------------")
	for i := uint64(111150718); i <= 111150722; i++ {
		miner, node, err := CalcBlockSubsidy(i, &config.ChainParams, true, true)
		require.NoError(t, err)
		fmt.Println(i, miner, node)
	}

	// Output
	// 1404798 3 MASS 3 MASS
	// 1404799 3 MASS 3 MASS
	// 1404800 3 MASS 3 MASS
	// 1404801 57.6 MASS 6.4 MASS
	// 1404802 57.6 MASS 6.4 MASS
	// -------------------
	// 1480318 57.6 MASS 6.4 MASS
	// 1480319 57.6 MASS 6.4 MASS
	// 1480320 57.6 MASS 6.4 MASS
	// 1480321 28.8 MASS 3.2 MASS
	// 1480322 28.8 MASS 3.2 MASS
	// -------------------
	// 56100478 0.45 MASS 0.05 MASS
	// 56100479 0.45 MASS 0.05 MASS
	// 56100480 0.45 MASS 0.05 MASS
	// 56100481 0.225 MASS 0.025 MASS
	// 56100482 0.225 MASS 0.025 MASS
	// -------------------
	// 111150718 0.225 MASS 0.025 MASS
	// 111150719 0.225 MASS 0.025 MASS
	// 111150720 0.225 MASS 0.025 MASS
	// 111150721 0 MASS 0 MASS
	// 111150722 0 MASS 0 MASS
}
