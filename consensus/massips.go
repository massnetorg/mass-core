package consensus

import "math"

var (
	MASSIP0001Height         uint64 = 694000
	MASSIP0001MaxValidPeriod        = defaultMinFrozenPeriod * 24 // 1474560

	// disallow minting without binding
	MASSIP0002Height uint64 = math.MaxUint32 - 2 // example value TODO: this value is subject to change
	// disable old binding
	MASSIP0002WarmUpHeight         uint64 = math.MaxUint32 - 6002  // example value TODO: this value is subject to change
	MASSIP0002BindingLockedPeriod  uint64 = 0x00000000ffffffff - 1 // wire.SequenceLockTimeMask - 1
	MASSIP0002SetPoolPkCoinbaseFee        = 100000000              // 1 MASS
	MASSIP0002PayloadNonceGap             = 5
)
