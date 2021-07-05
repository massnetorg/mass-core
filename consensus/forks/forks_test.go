package forks

import (
	"fmt"
	"strings"
	"testing"

	"github.com/massnetorg/mass-core/consensus"
	"github.com/massnetorg/mass-core/massutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParams(t *testing.T) {
	for bl, str := range map[int]string{
		24: "0.006144 MASS",
		26: "0.026624 MASS",
		28: "0.112 MASS",
		30: "0.48 MASS",
		32: "2.048 MASS",
		34: "8.704 MASS",
		36: "36.864 MASS",
		38: "152 MASS",
		40: "640 MASS",
	} {
		amt := bindingPriceSinceGenesis[bl]
		require.True(t, str == amt.String())
	}

	for i := 0; i < len(bindingPriceSinceMASSIP0002)-1; i++ {
		require.True(t, bindingPriceSinceMASSIP0002[i].AccumulativeUpperBound.Cmp(bindingPriceSinceMASSIP0002[i+1].AccumulativeUpperBound) < 0)
	}

	for i := 0; i < len(bindingPriceSinceMASSIP0002); i++ {
		u, err := bindingPriceSinceMASSIP0002[i].PricePer32G.Value().MulInt(NumberOf32GOnePB)
		assert.NoError(t, err)
		u, err = u.MulInt(100)
		assert.NoError(t, err)
		price100PB, err := massutil.NewAmount(u)
		assert.NoError(t, err)
		fmt.Println((i+1)*100, bindingPriceSinceMASSIP0002[i], price100PB)
	}
}

func newAmount(i int) massutil.Amount {
	amt, err := massutil.NewAmountFromInt(int64(i))
	if err != nil {
		panic(err)
	}
	return amt
}

/*
100 &{1666666 MASS 0.50860595 MASS} 1666599.97696 MASS
200 &{3333332 MASS 0.50860595 MASS} 1666599.97696 MASS
300 &{4999998 MASS 0.50860595 MASS} 1666599.97696 MASS
400 &{6249998 MASS 0.38146972 MASS} 1249999.978496 MASS
500 &{7249998 MASS 0.30517578 MASS} 999999.995904 MASS
600 &{8083331 MASS 0.25430297 MASS} 833299.972096 MASS
700 &{8797616 MASS 0.21795654 MASS} 714199.990272 MASS
800 &{9422616 MASS 0.19073486 MASS} 624999.989248 MASS
900 &{9978171 MASS 0.16952514 MASS} 555499.978752 MASS
1000 &{10478171 MASS 0.15258789 MASS} 499999.997952 MASS
1100 &{10932716 MASS 0.13870239 MASS} 454499.991552 MASS
1200 &{11349382 MASS 0.12713623 MASS} 416599.998464 MASS
1300 &{11733997 MASS 0.1173706 MASS} 384599.98208 MASS
1400 &{12091139 MASS 0.10897827 MASS} 357099.995136 MASS
1500 &{12424472 MASS 0.10171508 MASS} 333299.974144 MASS
1600 &{12736972 MASS 0.09536743 MASS} 312499.994624 MASS
1700 &{13031089 MASS 0.08975219 MASS} 294099.976192 MASS
1800 &{13308866 MASS 0.08474731 MASS} 277699.985408 MASS
1900 &{13572023 MASS 0.08029174 MASS} 263099.973632 MASS
2000 &{13822023 MASS 0.07629394 MASS} 249999.982592 MASS
2100 &{14060118 MASS 0.07263183 MASS} 237999.980544 MASS
2200 &{14287390 MASS 0.06933593 MASS} 227199.975424 MASS
2300 &{14504781 MASS 0.06631469 MASS} 217299.976192 MASS
2400 &{14713114 MASS 0.06356811 MASS} 208299.982848 MASS
2500 &{14913114 MASS 0.06103515 MASS} 199999.97952 MASS
2600 &{15105421 MASS 0.0586853 MASS} 192299.99104 MASS
2700 &{15290606 MASS 0.05648803 MASS} 185099.976704 MASS
2800 &{15469177 MASS 0.05447387 MASS} 178499.977216 MASS
2900 &{15641590 MASS 0.0526123 MASS} 172399.98464 MASS
3000 &{15808256 MASS 0.05084228 MASS} 166599.983104 MASS
3100 &{15969546 MASS 0.04919433 MASS} 161199.980544 MASS
3200 &{16125796 MASS 0.04766845 MASS} 156199.97696 MASS
3300 &{16277311 MASS 0.04623413 MASS} 151499.997184 MASS
3400 &{16424369 MASS 0.04486083 MASS} 146999.967744 MASS
3500 &{16567226 MASS 0.0435791 MASS} 142799.99488 MASS
3600 &{16706114 MASS 0.04235839 MASS} 138799.972352 MASS
3700 &{16841249 MASS 0.04122924 MASS} 135099.973632 MASS
3800 &{16972827 MASS 0.04013061 MASS} 131499.982848 MASS
3900 &{17101032 MASS 0.03912353 MASS} 128199.983104 MASS
4000 &{17226032 MASS 0.03814697 MASS} 124999.991296 MASS
4100 &{17347983 MASS 0.03720092 MASS} 121899.974656 MASS
4200 &{17467030 MASS 0.03631591 MASS} 118999.973888 MASS
4300 &{17583309 MASS 0.03546142 MASS} 116199.981056 MASS
4400 &{17696945 MASS 0.03466796 MASS} 113599.971328 MASS
4500 &{17808056 MASS 0.03390502 MASS} 111099.969536 MASS
4600 &{17916751 MASS 0.03314208 MASS} 108599.967744 MASS
4700 &{18023133 MASS 0.03244018 MASS} 106299.981824 MASS
4800 &{18127299 MASS 0.03176879 MASS} 104099.971072 MASS
4900 &{18229339 MASS 0.03112792 MASS} 101999.968256 MASS
5000 &{18329339 MASS 0.03051757 MASS} 99999.973376 MASS
*/
func TestGetRequiredBinding(t *testing.T) {
	tests := []struct {
		name           string
		height         uint64
		plotsize       uint64
		bitlength      int
		networkBinding massutil.Amount
		expectRequired massutil.Amount
		expectErr      string
	}{
		{
			name:           "zero network binding",
			height:         consensus.MASSIP0002WarmUpHeight,
			plotsize:       32 * 1024 * 1024 * 1024,
			bitlength:      20,
			networkBinding: newAmount(0),
			expectRequired: newAmount(50860595),
		},
		{
			name:           "3 million MASS",
			height:         consensus.MASSIP0002WarmUpHeight,
			plotsize:       32 * 1024 * 1024 * 1024,
			bitlength:      20,
			networkBinding: newAmount(166666600000000),
			expectRequired: newAmount(50860595),
		},
		{
			name:           "3 million MASS + 1 Maxwell, enter next interval",
			height:         consensus.MASSIP0002WarmUpHeight,
			plotsize:       32 * 1024 * 1024 * 1024,
			bitlength:      20,
			networkBinding: newAmount(166666600000001),
			expectRequired: newAmount(50860595),
		},
		{
			name:           "zero plot size",
			height:         consensus.MASSIP0002WarmUpHeight,
			plotsize:       0,
			bitlength:      20,
			networkBinding: newAmount(166666600000001),
			expectRequired: newAmount(67138671),
			expectErr:      "unexpected zero plot size",
		},
		{
			name:           "1-byte plot size",
			height:         consensus.MASSIP0002WarmUpHeight,
			plotsize:       1,
			bitlength:      20,
			networkBinding: newAmount(166666600000001),
			expectRequired: newAmount(50860595),
		},
		{
			name:           "64GB - 1B",
			height:         consensus.MASSIP0002WarmUpHeight,
			plotsize:       32*1024*1024*1024*2 - 1,
			bitlength:      20,
			networkBinding: newAmount(300000000000001),
			expectRequired: newAmount(67138671),
		},
		{
			name:           "64GB",
			height:         consensus.MASSIP0002WarmUpHeight,
			plotsize:       32 * 1024 * 1024 * 1024 * 2,
			bitlength:      20,
			networkBinding: newAmount(300000000000001),
			expectRequired: newAmount(67138671 * 2),
		},
		{
			name:           "1TB and no pre calculated price found",
			height:         consensus.MASSIP0002WarmUpHeight,
			plotsize:       1024 * 1024 * 1024 * 1024,
			bitlength:      -1,
			networkBinding: newAmount(1767492400000001), // 1 Maxwell more than 3000PB
			expectRequired: newAmount(4919433 * 32),
		},
		{
			name:           "160TB and no pre calculated price found-2",
			height:         consensus.MASSIP0002WarmUpHeight,
			plotsize:       160 * 1024 * 1024 * 1024 * 1024,
			bitlength:      -1,
			networkBinding: newAmount(2009600700000000), // 4900PB
			expectRequired: newAmount(3112792 * 32 * 160),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			amt, err := GetRequiredBinding(test.height, test.plotsize, test.bitlength, test.networkBinding)
			if test.expectErr == "" {
				assert.NoError(t, err)
			} else {
				assert.True(t, err != nil && strings.Contains(err.Error(), test.expectErr))
			}
			if err == nil {
				assert.True(t, amt.Cmp(test.expectRequired) == 0, amt)
			}
		})
	}
}
