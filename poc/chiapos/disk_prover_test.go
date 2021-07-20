package chiapos_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/massnetorg/mass-core/poc/chiapos"
)

func TestDiskProver(t *testing.T) {
	dp, err := chiapos.NewDiskProver("./testplots/plot.dat", false)
	if err != nil {
		t.Fatalf("NewDiskProver: %s", err)
	}
	defer dp.Close()

	id := dp.ID()
	size := dp.Size()
	fmt.Println(dp.Filename(), id, size)

	challenge := [...]byte{2, 47, 180, 44, 8, 193, 45, 227, 166, 175, 5, 56, 128, 25, 152, 6, 83, 46, 121, 81, 95, 148, 232, 52, 97, 97, 33, 1, 249, 65, 47, 158}
	qs, err := dp.GetQualitiesForChallenge(challenge)
	if err != nil {
		t.Fatalf("GetQualitiesForChallenge: %s", err)
	}
	fmt.Println(qs)

	fp, err := dp.GetFullProof(challenge, 300)
	if err != nil {
		if strings.Contains(err.Error(), "No proof of space for this challenge") {
			t.Logf("GetFullProof: %s", err)
		} else {
			t.Fatalf("GetFullProof: %s", err)
		}
	}
	fmt.Println(fp)
}

// func TestGetInfo(t *testing.T) {
// 	dp, err := chiapos.NewDiskProver("./testplots/plot.dat", false)
// 	if err != nil {
// 		t.Fatalf("NewDiskProver: %s", err)
// 	}
// 	defer dp.Close()

// 	pi := dp.PlotInfo()
// 	fmt.Println(pi.FarmerPublicKey.Bytes(), pi.PoolPublicKey.Bytes())
// }
