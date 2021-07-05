package blockchain

import (
	"bytes"
	"testing"

	"github.com/massnetorg/mass-core/config"
	"github.com/massnetorg/mass-core/massutil"
	"github.com/massnetorg/mass-core/poc/chiapos"
	"github.com/stretchr/testify/require"
)

func TestBindPoolPkCoinbase(t *testing.T) {
	poolSk, err := chiapos.NewAugSchemeMPL().KeyGen([]byte("poolSeedpoolSeedpoolSeedpoolSeed"))
	require.NoError(t, err)
	poolPk, err := poolSk.GetG1()
	require.NoError(t, err)

	addr1, err := massutil.DecodeAddress("ms1qqerxc2rrgg07qekrtmwcmktf57a8xgknprm5e6muq8urfx7d8tlysgk23lx", &config.ChainParams)
	require.NoError(t, err)
	// addr2, err := massutil.DecodeAddress("ms1qq6gpx5w8a923wj87cm2q6v6wlyweu7383qk2rj22vtu8g6u7wgd9q5leanu", &config.ChainParams)
	// require.NoError(t, err)

	t.Run("valid address", func(t *testing.T) {
		sig, err := SignPoolPkPayload(poolSk, addr1.ScriptAddress(), 1)
		require.NoError(t, err)

		ok, err := VerifyPoolPkPayload(poolPk, sig, addr1.ScriptAddress(), 1)
		require.NoError(t, err)
		require.True(t, ok)

		payload := NewBindPoolCoinbasePayload(poolPk, sig, addr1.ScriptAddress(), 1)
		encoded := EncodePayload(payload)
		require.True(t, len(encoded) == 182)

		decodedPayload := DecodePayload(encoded)
		require.True(t, payload.Method == decodedPayload.Method && payload.Method == BindPoolCoinbase)

		params := decodedPayload.Params.(*BindPoolCoinbaseParams)
		require.True(t, bytes.Equal(params.PoolPK.Bytes(), poolPk.Bytes()) &&
			bytes.Equal(params.Signature.Bytes(), sig.Bytes()) &&
			bytes.Equal(params.CoinbaseScriptAddress, addr1.ScriptAddress()) &&
			params.Nonce == 1,
		)
	})

	t.Run("nil address", func(t *testing.T) {
		sig, err := SignPoolPkPayload(poolSk, nil, 1)
		require.NoError(t, err)

		ok, err := VerifyPoolPkPayload(poolPk, sig, []byte{}, 1)
		require.NoError(t, err)
		require.True(t, ok)

		payload := NewBindPoolCoinbasePayload(poolPk, sig, []byte{}, 1)
		require.NotNil(t, payload)

		encoded := EncodePayload(payload)
		require.True(t, len(encoded) == 150)

		decodedPayload := DecodePayload(encoded)
		require.True(t, payload.Method == decodedPayload.Method && payload.Method == BindPoolCoinbase)

		params := decodedPayload.Params.(*BindPoolCoinbaseParams)
		require.True(t, bytes.Equal(params.PoolPK.Bytes(), poolPk.Bytes()) &&
			bytes.Equal(params.Signature.Bytes(), sig.Bytes()) &&
			len(params.CoinbaseScriptAddress) == 0 &&
			params.Nonce == 1,
		)
	})
}
