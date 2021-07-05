package poc

import (
	"math/big"

	"github.com/shopspring/decimal"
)

const (
	iterativeMPrecision       = 256
	iterativeDecimalPrecision = 256
)

var (
	//bigDecimalZero = decimal.NewFromInt(0)
	bigDecimalOne  = decimal.NewFromInt(1)
	bigDecimalTwo  = decimal.NewFromInt(2)
	power2Table    [257]*big.Int
	negPower2Table [257]decimal.Decimal
)

func init() {
	// fill negPower2Table
	negPower2Table[0] = decimal.NewFromInt(1)
	for i := 1; i <= 256; i++ {
		negPower2Table[i] = negPower2Table[i-1].DivRound(bigDecimalTwo, iterativeDecimalPrecision)
	}
	// fill power2Table
	var bigTwo = big.NewInt(2)
	power2Table[0] = big.NewInt(1)
	for i := 1; i <= 256; i++ {
		power2Table[i] = new(big.Int).Mul(power2Table[i-1], bigTwo)
	}
}

func log2ByIterative(hi *big.Int) decimal.Decimal {
	p, r := extractH(hi) // hi = 2^p + r
	y := decimal.NewFromBigInt(r, 0)
	y = y.DivRound(decimal.NewFromBigInt(power2Table[p], 0), iterativeDecimalPrecision)
	y = y.Add(bigDecimalOne) // y = 1 + r / (2^p), 1 <= y < 2
	log2Y := iterativeLog2(y)
	pd := decimal.NewFromInt(int64(p))
	return pd.Add(log2Y)
}

func iterativeLog2(y decimal.Decimal) decimal.Decimal {
	if y.Equal(bigDecimalOne) {
		return decimal.NewFromInt(0)
	}
	if y.Equal(bigDecimalTwo) {
		return decimal.NewFromInt(1)
	}
	var result = decimal.NewFromInt(0)
	var m, accumulatedM int
	var z = y.Mul(bigDecimalTwo)
	var ok bool
	for {
		m, z, ok = iterativeLog2GetM(z.DivRound(bigDecimalTwo, iterativeDecimalPrecision), accumulatedM)
		if !ok {
			break
		}
		accumulatedM += m
		result = result.Add(negPower2Table[accumulatedM])
	}
	return result
}

func iterativeLog2GetM(y decimal.Decimal, accumulatedM int) (m int, z decimal.Decimal, ok bool) {
	z = decimal.NewFromInt(0).Add(y)
	for m+accumulatedM < iterativeMPrecision {
		m++
		z = z.Mul(z)
		z = z.Round(iterativeDecimalPrecision)
		if z.GreaterThanOrEqual(bigDecimalTwo) {
			return m, z, true
		}
	}
	return iterativeMPrecision + 1, z, false
}

func calcQualityByDecimal(bl int, h *big.Int, log2Func func(*big.Int) decimal.Decimal) *big.Int {
	// Note: Q1 = SIZE * BL
	Q1 := decimal.NewFromInt(int64(1 << uint(bl) * bl))

	// Note: log2FH = log2(H)
	log2FH := log2Func(h)

	// Note: Q2 = 256 - log2(H)
	Q2 := decimal.NewFromInt(256)
	Q2 = Q2.Sub(log2FH)
	if Q2.Cmp(decimal.NewFromInt(0)) <= 0 {
		panic("Zero")
	}

	Quality := Q1.DivRound(Q2, iterativeDecimalPrecision).BigInt()
	return Quality
}

// extractH takes hi ranges in (0, 2^257)
func extractH(hi *big.Int) (exp int, r *big.Int) {
	for i := 256; i >= 0; i-- {
		t := power2Table[i]
		c := hi.Cmp(t)
		if c < 0 {
			continue
		}
		return i, new(big.Int).Sub(hi, t)
	}
	panic(hi.String())
}

func (proof *DefaultProof) GetQualityByIterative(slot, height uint64) *big.Int {
	hashVal := proof.GetHashVal(slot, height)
	// Note: Q1 = SIZE * BL
	Q1 := decimal.NewFromInt(int64(1 << uint(proof.BL) * proof.BL))

	// Note: BH = H in BigInt
	BH := new(big.Int).SetBytes(hashVal[:])

	// Note: log2FH = log2(H)
	log2FH := log2ByIterative(BH)

	// Note: Q2 = 256 - log2(H)
	Q2 := decimal.NewFromInt(256)
	Q2 = Q2.Sub(log2FH)
	if Q2.Cmp(decimal.NewFromInt(0)) <= 0 {
		panic("Zero")
	}

	Quality := Q1.DivRound(Q2, iterativeDecimalPrecision).BigInt()
	return Quality
}
