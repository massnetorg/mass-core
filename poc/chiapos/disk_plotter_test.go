package chiapos_test

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"testing"

	"github.com/massnetorg/mass-core/poc/chiapos"
	"github.com/stretchr/testify/require"
)

func TestK21(t *testing.T) {

	plotSeed := []byte{
		5, 104, 52, 4, 51, 55, 23, 84, 91, 10,
		111, 12, 13, 222, 151, 16, 228, 211, 254,
		45, 92, 198, 204, 10, 9, 10, 11, 129, 139, 171, 15, 23,
	}

	pl, err := chiapos.NewDiskPlotter()
	require.NoError(t, err)
	err = pl.CreatePlotDisk(".", ".", ".", "myplot.dat",
		21, []byte{1, 2, 3, 4, 5}, plotSeed,
		300, 32, 8192, 8,
		false)
	require.NoError(t, err)
	pl.Close()

	pr, err := chiapos.NewDiskProver("myplot.dat", false)
	require.NoError(t, err)

	v := chiapos.NewProofVerifier()
	defer v.Free()

	iterations := 5000
	totalProofs := 0

	for i := 0; i < iterations; i++ {

		var data [4]byte
		binary.BigEndian.PutUint32(data[:], uint32(i))
		challenge := sha256.Sum256(data[:])
		if i%100 == 0 {
			fmt.Println(i, hex.EncodeToString(data[:]), hex.EncodeToString(challenge[:]))
		}

		qualities, err := pr.GetQualitiesForChallenge(challenge)
		require.NoError(t, err)
		for index, quality := range qualities {
			proof, err := pr.GetFullProof(challenge, uint32(index))
			require.NoError(t, err)
			require.True(t, len(proof) == int(8*pr.Size()), fmt.Sprintf("expect proof size %d, actual %d", 8*int(pr.Size()), len(proof)))

			computedQuality, err := v.GetVerifiedQuality(plotSeed, proof, challenge, int(pr.Size()))
			require.NoError(t, err)
			require.Equal(t, computedQuality, quality)

			totalProofs++
		}
	}
	fmt.Printf("total proofs %d out of %d\n", totalProofs, iterations)
	require.True(t, totalProofs > 4000 && totalProofs < 6000)

	pr.Close()

	f, err := os.Open("myplot.dat")
	require.NoError(t, err)
	defer f.Close()

	br := bufio.NewReader(f)
	chunk := make([]byte, 4096)
	hasher := sha256.New()
	for {
		n, err := br.Read(chunk)
		if err != nil {
			if err == io.EOF {
				t.Logf("read %d when eof", n)
				break
			}
			t.Fatalf("read file failed: %v", err)
		}
		_, err = hasher.Write(chunk[:n])
		require.NoError(t, err)
	}
	plotHash := hasher.Sum(nil)
	require.True(t, "80e32f560f3a4347760d6baae8d16fbaf484948088bff05c51bdcc24b7bc40d9" == hex.EncodeToString(plotHash))
}

func TestFaultyPlotDoesntCrash(t *testing.T) {
	os.Remove("myplot.dat")
	os.Remove("myplotbad.dat")

	plotID := []byte{32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63}
	pl, err := chiapos.NewDiskPlotter()
	require.NoError(t, err)
	defer pl.Close()
	err = pl.CreatePlotDisk(".", ".", ".", "myplot.dat",
		21, []byte{1, 2, 3, 4, 5}, plotID,
		300, 32, 8192, 8,
		false)
	require.NoError(t, err)

	f, err := os.Open("myplot.dat")
	require.NoError(t, err)
	defer f.Close()
	allData, err := ioutil.ReadAll(f)
	require.NoError(t, err)
	require.True(t, len(allData) > 20000000)

	var chip [10000]byte
	n, err := rand.Read(chip[:])
	require.NoError(t, err)
	require.True(t, n == 10000)
	allBadData := append(allData[:20000000], chip[:]...)
	allBadData = append(allBadData, allData[20100000:]...)

	err = ioutil.WriteFile("myplotbad.dat", allBadData, 0700)
	require.NoError(t, err)

	pr, err := chiapos.NewDiskProver("myplotbad.dat", false)
	require.NoError(t, err)
	defer pr.Close()

	v := chiapos.NewProofVerifier()
	defer v.Free()
	iterations := 50000
	successes := 0
	failures := 0

	for i := 0; i < iterations; i++ {
		var data [4]byte
		binary.BigEndian.PutUint32(data[:], uint32(i))
		challenge := sha256.Sum256(data[:])
		if i%100 == 0 {
			fmt.Println(i, hex.EncodeToString(data[:]), hex.EncodeToString(challenge[:]))
		}

		qualities, err := pr.GetQualitiesForChallenge(challenge)
		if err != nil {
			t.Log(err)
			failures++
			continue
		}
		for index, quality := range qualities {
			proof, err := pr.GetFullProof(challenge, uint32(index))
			require.NoError(t, err)
			require.True(t, len(proof) == int(8*pr.Size()), fmt.Sprintf("expect proof size %d, actual %d", 8*int(pr.Size()), len(proof)))

			computedQuality, err := v.GetVerifiedQuality(plotID, proof, challenge, int(pr.Size()))
			require.NoError(t, err)
			require.Equal(t, computedQuality, quality)
			if bytes.Equal(computedQuality, quality) {
				successes++
			} else {
				failures++
			}
		}
	}
	fmt.Printf("successes %d, failures %d\n", successes, failures)
}
