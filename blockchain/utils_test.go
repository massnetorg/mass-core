package blockchain

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/massnetorg/mass-core/blockchain/state"
	"github.com/massnetorg/mass-core/config"
	"github.com/massnetorg/mass-core/massutil"
	"github.com/massnetorg/mass-core/poc/chiapos"
	"github.com/massnetorg/mass-core/trie/common"
	"github.com/massnetorg/mass-core/trie/rawdb"
	"github.com/stretchr/testify/require"
)

func TestPutGetPoolPkCoinbase(t *testing.T) {
	stateDb := state.NewDatabase(rawdb.NewMemoryDatabase())
	trie, err := stateDb.OpenBindingTrie(common.Hash{})
	require.NoError(t, err)

	poolSk, err := chiapos.NewAugSchemeMPL().KeyGen([]byte("poolSeedpoolSeedpoolSeedpoolSeed"))
	require.NoError(t, err)
	poolPk, err := poolSk.GetG1()
	require.NoError(t, err)

	coinbase, err := massutil.DecodeAddress("ms1qqerxc2rrgg07qekrtmwcmktf57a8xgknprm5e6muq8urfx7d8tlysgk23lx", &config.ChainParams)
	require.NoError(t, err)

	// save
	sig, err := SignPoolPkPayload(poolSk, coinbase.ScriptAddress(), 1)
	require.NoError(t, err)
	payload := NewBindPoolCoinbasePayload(poolPk, sig, coinbase.ScriptAddress(), 1)
	err = CheckNonceAndSetPoolPkCoinbase(trie, EncodePayload(payload))
	require.NoError(t, err)

	// get
	raw, nonce, err := GetPoolPkCoinbase(trie, poolPk.Bytes())
	require.NoError(t, err)
	var nonceBuf [4]byte
	binary.BigEndian.PutUint32(nonceBuf[:], 1)
	require.True(t, raw != nil && bytes.Equal(raw, coinbase.ScriptAddress()) && nonce == 1)

	// update
	coinbase2, err := massutil.DecodeAddress("ms1qq6gpx5w8a923wj87cm2q6v6wlyweu7383qk2rj22vtu8g6u7wgd9q5leanu", &config.ChainParams)
	require.NoError(t, err)

	sig2, err := SignPoolPkPayload(poolSk, coinbase2.ScriptAddress(), 2)
	require.NoError(t, err)
	payload2 := NewBindPoolCoinbasePayload(poolPk, sig2, coinbase2.ScriptAddress(), 2)
	err = CheckNonceAndSetPoolPkCoinbase(trie, EncodePayload(payload2))
	require.NoError(t, err)

	raw, nonce, err = GetPoolPkCoinbase(trie, poolPk.Bytes())
	require.NoError(t, err)
	binary.BigEndian.PutUint32(nonceBuf[:], 1)
	require.True(t, raw != nil && bytes.Equal(raw, coinbase2.ScriptAddress()) && nonce == 2)

	// delete
	sig3, err := SignPoolPkPayload(poolSk, nil, 3)
	require.NoError(t, err)
	payload3 := NewBindPoolCoinbasePayload(poolPk, sig3, []byte{}, 3)
	err = CheckNonceAndSetPoolPkCoinbase(trie, EncodePayload(payload3))
	require.NoError(t, err)

	raw, nonce, err = GetPoolPkCoinbase(trie, poolPk.Bytes())
	require.NoError(t, err)
	require.True(t, len(raw) == 0, raw)
}

func TestGetPutNetworkBinding(t *testing.T) {
	stateDb := state.NewDatabase(rawdb.NewMemoryDatabase())
	trie, err := stateDb.OpenBindingTrie(common.Hash{})
	require.NoError(t, err)

	amt, err := GetNetworkBinding(trie)
	require.NoError(t, err)
	require.True(t, amt.IsZero())

	amt, _ = massutil.NewAmountFromInt(1000)
	err = PutNetworkBinding(trie, amt)
	require.NoError(t, err)

	amt, err = GetNetworkBinding(trie)
	require.NoError(t, err)
	require.True(t, amt.IntValue() == 1000)
}
