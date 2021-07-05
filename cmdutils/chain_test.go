package cmdutils

import (
	"testing"

	"github.com/massnetorg/mass-core/config"
)

func TestImport(t *testing.T) {
	bc, close, err := MakeChain("chain", false, &config.ChainParams)
	if err != nil {
		t.Fatal(err)
	}
	defer close()

	err = ImportChain(bc, "archive", true)
	if err != nil {
		t.Fatal(err)
	}
}
