package chiapos_test

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"strconv"
	"testing"

	"github.com/massnetorg/mass-core/poc/chiapos"
	"github.com/stretchr/testify/require"
)

type Scheme interface {
	Sign(sk *chiapos.PrivateKey, data []byte) (*chiapos.G2Element, error)
	Verify(pk *chiapos.G1Element, data []byte, signature *chiapos.G2Element) (bool, error)
	Aggregate(signatures ...*chiapos.G2Element) (*chiapos.G2Element, error)
	AggregateVerify(pks []*chiapos.G1Element, datas [][]byte, signature *chiapos.G2Element) (bool, error)
	DeriveChildSk(sk *chiapos.PrivateKey, index int) (*chiapos.PrivateKey, error)
	DeriveChildSkUnhardened(sk *chiapos.PrivateKey, index int) (*chiapos.PrivateKey, error)
	DeriveChildPkUnhardened(pk *chiapos.G1Element, index int) (*chiapos.G1Element, error)
}

func TestSchemes(t *testing.T) {

	seed := []byte{
		0, 50, 6, 244, 24, 199, 1, 25, 52, 88, 192, 19, 18, 12, 89, 6,
		220, 18, 102, 58, 209, 82, 12, 62, 89, 110, 182, 9, 44, 20, 254, 22,
	}
	msg := []byte{100, 2, 254, 88, 90, 45, 23}
	msg2 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	sk, err := chiapos.NewBasicSchemeMPL().KeyGen(seed)
	require.NoError(t, err)
	pk, err := sk.GetG1()
	require.NoError(t, err)

	recoverPk, err := chiapos.NewG1ElementFromBytes(pk.Bytes())
	require.NoError(t, err)
	require.True(t, len(pk.Bytes()) != 0 && recoverPk.Equals(pk))

	recoverSk, err := chiapos.NewPrivateKeyFromBytes(sk.Bytes())
	require.NoError(t, err)
	require.True(t, len(sk.Bytes()) != 0 && recoverSk.Equals(sk))

	for i, scheme := range []Scheme{
		chiapos.NewAugSchemeMPL(),
		chiapos.NewBasicSchemeMPL(),
		chiapos.NewPopSchemeMPL(),
	} {
		sig, err := scheme.Sign(sk, msg)
		require.NoError(t, err)

		sigBytes := sig.Bytes()
		recoverSig, err := chiapos.NewG2ElementFromBytes(sigBytes)
		require.NoError(t, err)
		require.True(t, len(sigBytes) != 0 && recoverSig.Equals(sig))

		ok, err := scheme.Verify(pk, msg, sig)
		require.NoError(t, err)
		require.True(t, ok, i)
	}

	seed = append([]byte{1}, seed[1:]...)
	sk1, err := chiapos.NewBasicSchemeMPL().KeyGen(seed)
	require.NoError(t, err)
	pk1, err := sk1.GetG1()
	require.NoError(t, err)
	seed = append([]byte{2}, seed[1:]...)
	sk2, err := chiapos.NewBasicSchemeMPL().KeyGen(seed)
	require.NoError(t, err)
	pk2, err := sk2.GetG1()
	require.NoError(t, err)

	for _, scheme := range []Scheme{
		chiapos.NewBasicSchemeMPL(),
		chiapos.NewAugSchemeMPL(),
		chiapos.NewPopSchemeMPL(),
	} {
		var sig1, sig2 *chiapos.G2Element

		agg_pk, err := pk1.Add(pk2)
		require.NoError(t, err)

		switch mpl := scheme.(type) {
		case *chiapos.AugSchemeMPL:
			sig1, err = mpl.SignPrepend(sk1, msg, agg_pk)
			require.NoError(t, err)
			sig2, err = mpl.SignPrepend(sk2, msg, agg_pk)
			require.NoError(t, err)
		default:
			sig1, err = mpl.Sign(sk1, msg)
			require.NoError(t, err)
			sig2, err = mpl.Sign(sk2, msg)
			require.NoError(t, err)
		}

		agg_sig, err := scheme.Aggregate(sig1, sig2)
		require.NoError(t, err)

		ok, err := scheme.Verify(agg_pk, msg, agg_sig)
		require.NoError(t, err)
		require.True(t, ok)

		// Aggregate different message
		sig1, err = scheme.Sign(sk1, msg)
		require.NoError(t, err)
		sig2, err = scheme.Sign(sk2, msg2)
		require.NoError(t, err)
		agg_sig, err = scheme.Aggregate(sig1, sig2)
		require.NoError(t, err)

		ok, err = scheme.AggregateVerify([]*chiapos.G1Element{pk1, pk2}, [][]byte{msg, msg2}, agg_sig)
		require.NoError(t, err)
		require.True(t, ok)

		// HD keys
		child, err := scheme.DeriveChildSk(sk1, 123)
		require.NoError(t, err)
		childU, err := scheme.DeriveChildSkUnhardened(sk1, 123)
		require.NoError(t, err)
		childUPk, err := scheme.DeriveChildPkUnhardened(pk1, 123)
		require.NoError(t, err)

		sigChild, err := scheme.Sign(child, msg)
		require.NoError(t, err)
		childPk, err := child.GetG1()
		require.NoError(t, err)
		ok, err = scheme.Verify(childPk, msg, sigChild)
		require.NoError(t, err)
		require.True(t, ok)

		sigUChild, err := scheme.Sign(childU, msg)
		require.NoError(t, err)
		ok, err = scheme.Verify(childUPk, msg, sigUChild)
		require.NoError(t, err)
		require.True(t, ok)
	}
}

func TestVectorsInvalid(t *testing.T) {
	// Invalid inputs from https://github.com/algorand/bls_sigs_ref/blob/master/python-impl/serdesZ.py
	invalidInputs1 := []string{
		// infinity points: too short
		"c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		// infinity points: not all zeros
		"c00000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000",
		// bad tags
		"3a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa",
		"7a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa",
		"fa0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa",
		// wrong length for compresed point
		"9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa",
		"9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaaaa",
		// invalid x-coord
		"9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa",
		// invalid elm of Fp --- equal to p (must be strictly less)
		"9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
	}
	invalidInputs2 := []string{
		// infinity points: too short
		"c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		// infinity points: not all zeros
		"c00000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000",
		// bad tags
		"3a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"7a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"fa0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		// wrong length for compressed point
		"9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		// invalid x-coord
		"9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaa7",
		// invalid elm of Fp --- equal to p (must be strictly less)
		"9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
	}

	for i, s := range invalidInputs1 {
		bytes, err := hex.DecodeString(s)
		require.NoError(t, err)
		_, err = chiapos.NewG1ElementFromBytes(bytes)
		require.Error(t, err, "failed to disallow creation of G1 element", bytes)
		if err != nil {
			t.Log(i, err)
		}
	}

	for i, s := range invalidInputs2 {
		bytes, err := hex.DecodeString(s)
		require.NoError(t, err)
		_, err = chiapos.NewG2ElementFromBytes(bytes)
		require.Error(t, err, "failed to disallow creation of G2 element")
		if err != nil {
			t.Log(i, err)
		}
	}
}

func TestVectorsValid(t *testing.T) {
	/*
			 from py_ecc.bls import (
		        G2Basic,
		        G2MessageAugmentation as G2MA,
		        G2ProofOfPossession as G2Pop,
		    )

		    secret1 = bytes([1] * 32)
		    secret2 = bytes([x * 314159 % 256 for x in range(32)])
		    sk1 = int.from_bytes(secret1, 'big')
		    sk2 = int.from_bytes(secret2, 'big')
		    msg = bytes([3, 1, 4, 1, 5, 9])
		    pk1 = G2Basic.SkToPk(sk1)
		    pk2 = G2Basic.SkToPk(sk2)

		    for Scheme in (G2Basic, G2MA, G2Pop):
		        sig1 = Scheme.Sign(sk1, msg)
		        sig2 = Scheme.Sign(sk2, msg)
		        sig_agg = Scheme.Aggregate([sig1, sig2])
		        print(sig1)
		        print(sig2)
		        print(sig_agg)
	*/

	ref_sig1Basic, err := hex.DecodeString("96ba34fac33c7f129d602a0bc8a3d43f9abc014eceaab7359146b4b150e57b808645738f35671e9e10e0d862a30cab70074eb5831d13e6a5b162d01eebe687d0164adbd0a864370a7c222a2768d7704da254f1bf1823665bc2361f9dd8c00e99")
	require.NoError(t, err)
	ref_sig2Basic, err := hex.DecodeString("a402790932130f766af11ba716536683d8c4cfa51947e4f9081fedd692d6dc0cac5b904bee5ea6e25569e36d7be4ca59069a96e34b7f700758b716f9494aaa59a96e74d14a3b552a9a6bc129e717195b9d6006fd6d5cef4768c022e0f7316abf")
	require.NoError(t, err)
	ref_sigABasic, err := hex.DecodeString("987cfd3bcd62280287027483f29c55245ed831f51dd6bd999a6ff1a1f1f1f0b647778b0167359c71505558a76e158e66181ee5125905a642246b01e7fa5ee53d68a4fe9bfb29a8e26601f0b9ad577ddd18876a73317c216ea61f430414ec51c5")
	require.NoError(t, err)
	ref_sig1Aug, err := hex.DecodeString("8180f02ccb72e922b152fcedbe0e1d195210354f70703658e8e08cbebf11d4970eab6ac3ccf715f3fb876df9a9797abd0c1af61aaeadc92c2cfe5c0a56c146cc8c3f7151a073cf5f16df38246724c4aed73ff30ef5daa6aacaed1a26ecaa336b")
	require.NoError(t, err)
	ref_sig2Aug, err := hex.DecodeString("99111eeafb412da61e4c37d3e806c6fd6ac9f3870e54da9222ba4e494822c5b7656731fa7a645934d04b559e9261b86201bbee57055250a459a2da10e51f9c1a6941297ffc5d970a557236d0bdeb7cf8ff18800b08633871a0f0a7ea42f47480")
	require.NoError(t, err)
	ref_sigAAug, err := hex.DecodeString("8c5d03f9dae77e19a5945a06a214836edb8e03b851525d84b9de6440e68fc0ca7303eeed390d863c9b55a8cf6d59140a01b58847881eb5af67734d44b2555646c6616c39ab88d253299acc1eb1b19ddb9bfcbe76e28addf671d116c052bb1847")
	require.NoError(t, err)
	ref_sig1Pop, err := hex.DecodeString("9550fb4e7f7e8cc4a90be8560ab5a798b0b23000b6a54a2117520210f986f3f281b376f259c0b78062d1eb3192b3d9bb049f59ecc1b03a7049eb665e0df36494ae4cb5f1136ccaeefc9958cb30c3333d3d43f07148c386299a7b1bfc0dc5cf7c")
	require.NoError(t, err)
	ref_sig2Pop, err := hex.DecodeString("a69036bc11ae5efcbf6180afe39addde7e27731ec40257bfdc3c37f17b8df68306a34ebd10e9e32a35253750df5c87c2142f8207e8d5654712b4e554f585fb6846ff3804e429a9f8a1b4c56b75d0869ed67580d789870babe2c7c8a9d51e7b2a")
	require.NoError(t, err)
	ref_sigAPop, err := hex.DecodeString("a4ea742bcdc1553e9ca4e560be7e5e6c6efa6a64dddf9ca3bb2854233d85a6aac1b76ec7d103db4e33148b82af9923db05934a6ece9a7101cd8a9d47ce27978056b0f5900021818c45698afdd6cf8a6b6f7fee1f0b43716f55e413d4b87a6039")
	require.NoError(t, err)

	secret1 := [32]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	secret2 := [32]byte{}
	for i := 0; i < 32; i++ {
		secret2[i] = byte(i * 314159 % 256)
	}
	sk1, err := chiapos.NewPrivateKeyFromBytes(secret1[:])
	require.NoError(t, err)
	sk2, err := chiapos.NewPrivateKeyFromBytes(secret2[:])
	require.NoError(t, err)

	msg := []byte{3, 1, 4, 1, 5, 9}

	sig1Basic, err := chiapos.NewBasicSchemeMPL().Sign(sk1, msg)
	require.NoError(t, err)
	sig2Basic, err := chiapos.NewBasicSchemeMPL().Sign(sk2, msg)
	require.NoError(t, err)
	sigABasic, err := chiapos.NewBasicSchemeMPL().Aggregate(sig1Basic, sig2Basic)
	require.NoError(t, err)
	require.Equal(t, ref_sig1Basic, sig1Basic.Bytes())
	require.Equal(t, ref_sig2Basic, sig2Basic.Bytes())
	require.Equal(t, ref_sigABasic, sigABasic.Bytes())

	sig1Aug, err := chiapos.NewAugSchemeMPL().Sign(sk1, msg)
	require.NoError(t, err)
	sig2Aug, err := chiapos.NewAugSchemeMPL().Sign(sk2, msg)
	require.NoError(t, err)
	sigAAug, err := chiapos.NewAugSchemeMPL().Aggregate(sig1Aug, sig2Aug)
	require.NoError(t, err)
	require.Equal(t, ref_sig1Aug, sig1Aug.Bytes())
	require.Equal(t, ref_sig2Aug, sig2Aug.Bytes())
	require.Equal(t, ref_sigAAug, sigAAug.Bytes())

	sig1Pop, err := chiapos.NewPopSchemeMPL().Sign(sk1, msg)
	require.NoError(t, err)
	sig2Pop, err := chiapos.NewPopSchemeMPL().Sign(sk2, msg)
	require.NoError(t, err)
	sigAPop, err := chiapos.NewPopSchemeMPL().Aggregate(sig1Pop, sig2Pop)
	require.NoError(t, err)
	require.Equal(t, ref_sig1Pop, sig1Pop.Bytes())
	require.Equal(t, ref_sig2Pop, sig2Pop.Bytes())
	require.Equal(t, ref_sigAPop, sigAPop.Bytes())
}

func TestReadme(t *testing.T) {
	seed := []byte{
		0, 50, 6, 244, 24, 199, 1, 25, 52, 88, 192, 19, 18, 12,
		89, 6, 220, 18, 102, 58, 209, 82, 12,
		62, 89, 110, 182, 9, 44, 20, 254, 22,
	}

	sk, err := chiapos.NewAugSchemeMPL().KeyGen(seed)
	require.NoError(t, err)
	pk, err := sk.GetG1()
	require.NoError(t, err)

	message := []byte{1, 2, 3, 4, 5}
	signature, err := chiapos.NewAugSchemeMPL().Sign(sk, message)
	require.NoError(t, err)
	ok, err := chiapos.NewAugSchemeMPL().Verify(pk, message, signature)
	require.NoError(t, err)
	require.True(t, ok)

	sk_bytes := sk.Bytes()
	pk_bytes := pk.Bytes()
	signature_bytes := signature.Bytes()
	fmt.Println(hex.EncodeToString(sk_bytes), hex.EncodeToString(pk_bytes), hex.EncodeToString(signature_bytes))

	sk, err = chiapos.NewPrivateKeyFromBytes(sk_bytes)
	require.NoError(t, err)
	pk, err = chiapos.NewG1ElementFromBytes(pk_bytes)
	require.NoError(t, err)
	signature, err = chiapos.NewG2ElementFromBytes(signature_bytes)
	require.NoError(t, err)

	// aggregate 2
	seed = append([]byte{1}, seed[1:]...)
	sk1, err := chiapos.NewAugSchemeMPL().KeyGen(seed)
	require.NoError(t, err)
	seed = append([]byte{2}, seed[1:]...)
	sk2, err := chiapos.NewAugSchemeMPL().KeyGen(seed)
	require.NoError(t, err)
	message2 := []byte{1, 2, 3, 4, 5, 6, 7}

	pk1, err := sk1.GetG1()
	require.NoError(t, err)
	sig1, err := chiapos.NewAugSchemeMPL().Sign(sk1, message)
	require.NoError(t, err)

	pk2, err := sk2.GetG1()
	require.NoError(t, err)
	sig2, err := chiapos.NewAugSchemeMPL().Sign(sk2, message2)
	require.NoError(t, err)

	agg_sig, err := chiapos.NewAugSchemeMPL().Aggregate(sig1, sig2)
	require.NoError(t, err)

	ok, err = chiapos.NewAugSchemeMPL().AggregateVerify([]*chiapos.G1Element{pk1, pk2}, [][]byte{message, message2}, agg_sig)
	require.NoError(t, err)
	require.True(t, ok)

	// aggregate 3
	seed = append([]byte{3}, seed[1:]...)
	sk3, err := chiapos.NewAugSchemeMPL().KeyGen(seed)
	require.NoError(t, err)
	pk3, err := sk3.GetG1()
	require.NoError(t, err)
	message3 := []byte{100, 2, 254, 88, 90, 45, 23}
	sig3, err := chiapos.NewAugSchemeMPL().Sign(sk3, message3)
	require.NoError(t, err)

	agg_sig_final, err := chiapos.NewAugSchemeMPL().Aggregate(agg_sig, sig3)
	require.NoError(t, err)
	ok, err = chiapos.NewAugSchemeMPL().AggregateVerify([]*chiapos.G1Element{pk1, pk2, pk3}, [][]byte{message, message2, message3}, agg_sig_final)
	require.NoError(t, err)
	require.True(t, ok)

	// pop
	pop_sig1, err := chiapos.NewPopSchemeMPL().Sign(sk1, message)
	require.NoError(t, err)
	pop_sig2, err := chiapos.NewPopSchemeMPL().Sign(sk2, message)
	require.NoError(t, err)
	pop_sig3, err := chiapos.NewPopSchemeMPL().Sign(sk3, message)
	require.NoError(t, err)
	pop1, err := chiapos.NewPopSchemeMPL().PopProve(sk1)
	require.NoError(t, err)
	pop2, err := chiapos.NewPopSchemeMPL().PopProve(sk2)
	require.NoError(t, err)
	pop3, err := chiapos.NewPopSchemeMPL().PopProve(sk3)
	require.NoError(t, err)

	ok, err = chiapos.NewPopSchemeMPL().PopVerify(pk1, pop1)
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = chiapos.NewPopSchemeMPL().PopVerify(pk2, pop2)
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = chiapos.NewPopSchemeMPL().PopVerify(pk3, pop3)
	require.NoError(t, err)
	require.True(t, ok)

	pop_sig_agg, err := chiapos.NewPopSchemeMPL().Aggregate(pop_sig1, pop_sig2, pop_sig3)
	require.NoError(t, err)
	ok, err = chiapos.NewPopSchemeMPL().FastAggregateVerify([]*chiapos.G1Element{pk1, pk2, pk3}, message, pop_sig_agg)
	require.NoError(t, err)
	require.True(t, ok)

	pop_agg_pk, err := pk1.Add(pk2)
	require.NoError(t, err)
	pop_agg_pk, err = pop_agg_pk.Add(pk3)
	require.NoError(t, err)
	ok, err = chiapos.NewPopSchemeMPL().Verify(pop_agg_pk, message, pop_sig_agg)
	require.NoError(t, err)
	require.True(t, ok)

	pop_agg_sk, err := chiapos.AggregatePrivateKey(sk1, sk2, sk3)
	require.NoError(t, err)
	pop_agg_sig, err := chiapos.NewPopSchemeMPL().Sign(pop_agg_sk, message)
	require.NoError(t, err)
	require.True(t, pop_agg_sig.Equals(pop_sig_agg))

	// Aug
	master_sk, err := chiapos.NewAugSchemeMPL().KeyGen(seed)
	require.NoError(t, err)
	// child, err := chiapos.NewAugSchemeMPL().DeriveChildSk(master_sk, 152)
	// require.NoError(t, err)
	// grandchild, err := chiapos.NewAugSchemeMPL().DeriveChildSk(child, 952)
	// require.NoError(t, err)

	master_pk, err := master_sk.GetG1()
	require.NoError(t, err)
	child_u, err := chiapos.NewAugSchemeMPL().DeriveChildSkUnhardened(master_sk, 22)
	require.NoError(t, err)
	grandchild_u, err := chiapos.NewAugSchemeMPL().DeriveChildSkUnhardened(child_u, 0)
	require.NoError(t, err)

	child_u_pk, err := chiapos.NewAugSchemeMPL().DeriveChildPkUnhardened(master_pk, 22)
	require.NoError(t, err)
	grandchild_u_pk, err := chiapos.NewAugSchemeMPL().DeriveChildPkUnhardened(child_u_pk, 0)
	require.NoError(t, err)

	grandchild_u_g1, err := grandchild_u.GetG1()
	require.NoError(t, err)
	require.True(t, grandchild_u_pk.Equals(grandchild_u_g1))
}

func TestAggregateVerifyZeroItems(t *testing.T) {
	g2 := chiapos.NewG2Element()
	ok, err := chiapos.NewAugSchemeMPL().AggregateVerify(nil, nil, g2)
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = chiapos.NewBasicSchemeMPL().AggregateVerify(nil, nil, g2)
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = chiapos.NewPopSchemeMPL().AggregateVerify(nil, nil, g2)
	require.NoError(t, err)
	require.True(t, ok)
}

func prepareBenchmark(b *testing.B) (sig_bytes, pk_bytes, ms [][]byte) {

	for i := 0; i < b.N; i++ {
		var seed [32]byte
		n, err := rand.Read(seed[:])
		require.NoError(b, err)
		require.True(b, n == 32)
		message := []byte(strconv.Itoa(i))

		sk, err := chiapos.NewAugSchemeMPL().KeyGen(seed[:])
		require.NoError(b, err)
		pk, err := sk.GetG1()
		require.NoError(b, err)
		sig, err := chiapos.NewAugSchemeMPL().Sign(sk, message)
		require.NoError(b, err)

		sig_bytes = append(sig_bytes, sig.Bytes())
		pk_bytes = append(pk_bytes, pk.Bytes())
		ms = append(ms, message)

	}
	return
}

func BenchmarkPkFromBytes(b *testing.B) {
	_, pk_bytes, _ := prepareBenchmark(b)

	pks := make([]*chiapos.G1Element, 0, len(pk_bytes))

	b.ResetTimer()

	for _, bytes := range pk_bytes {
		pk, err := chiapos.NewG1ElementFromBytes(bytes)
		require.NoError(b, err)
		pks = append(pks, pk)
	}

	b.StopTimer()
}

func BenchmarkSigFromBytes(b *testing.B) {
	sig_bytes, _, _ := prepareBenchmark(b)

	sigs := make([]*chiapos.G2Element, 0, len(sig_bytes))

	b.ResetTimer()

	for _, bytes := range sig_bytes {
		sig, err := chiapos.NewG2ElementFromBytes(bytes)
		require.NoError(b, err)
		sigs = append(sigs, sig)
	}

	b.StopTimer()
}

func BenchmarkSigAggregate(b *testing.B) {
	sig_bytes, _, _ := prepareBenchmark(b)
	sigs := make([]*chiapos.G2Element, 0, len(sig_bytes))

	b.ResetTimer()

	for _, bytes := range sig_bytes {
		sig, err := chiapos.NewG2ElementFromBytes(bytes)
		require.NoError(b, err)
		sigs = append(sigs, sig)
	}

	_, err := chiapos.NewAugSchemeMPL().Aggregate(sigs...)
	require.NoError(b, err)
	b.StopTimer()
}

func BenchmarkAggregateVerify(b *testing.B) {
	sig_bytes, pk_bytes, ms := prepareBenchmark(b)
	require.True(b, len(sig_bytes) == len(pk_bytes))

	pks := make([]*chiapos.G1Element, 0, len(pk_bytes))
	sigs := make([]*chiapos.G2Element, 0, len(sig_bytes))

	for _, bytes := range pk_bytes {
		pk, err := chiapos.NewG1ElementFromBytes(bytes)
		require.NoError(b, err)
		pks = append(pks, pk)
	}
	for _, bytes := range sig_bytes {
		sig, err := chiapos.NewG2ElementFromBytes(bytes)
		require.NoError(b, err)
		sigs = append(sigs, sig)
	}
	agg_sig, err := chiapos.NewAugSchemeMPL().Aggregate(sigs...)
	require.NoError(b, err)

	b.ResetTimer()

	ok, err := chiapos.NewAugSchemeMPL().AggregateVerify(pks, ms, agg_sig)
	require.NoError(b, err)
	require.True(b, ok)

	b.StopTimer()
}
