package txscript

import (
	"crypto/sha256"
	"errors"

	"github.com/btcsuite/btcd/btcec"
	"github.com/massnetorg/mass-core/config"
	"github.com/massnetorg/mass-core/logging"
	"github.com/massnetorg/mass-core/massutil"
)

type MockWallet struct {
	WitnessMap      map[string][]byte            // witness address -> redeemscript
	PubKeyToPrivKey map[string]*btcec.PrivateKey // map key is string(pub key bytes)
}

func NewMockWallet() *MockWallet {
	return &MockWallet{
		WitnessMap:      make(map[string][]byte),
		PubKeyToPrivKey: make(map[string]*btcec.PrivateKey),
	}
}

func (w *MockWallet) FindRedeemScript(addr massutil.Address) []byte {
	return w.WitnessMap[addr.EncodeAddress()]
}

func (w *MockWallet) GetPrivKey(pk *btcec.PublicKey) *btcec.PrivateKey {
	return w.PubKeyToPrivKey[string(pk.SerializeCompressed())]
}

func (w *MockWallet) NewPublicKeys(n int) ([]*btcec.PublicKey, error) {
	var result []*btcec.PublicKey
	for n > 0 {
		privk, err := btcec.NewPrivateKey(btcec.S256())
		if err != nil {
			return nil, err
		}
		w.PubKeyToPrivKey[string(privk.PubKey().SerializeCompressed())] = privk
		result = append(result, privk.PubKey())
		n--
	}
	return result, nil
}

func (w *MockWallet) BuildBindingPkScript(nRequire, nTotal int, pocPkHash []byte) ([]byte, error) {
	pubKeys, err := w.NewPublicKeys(nTotal)
	if err != nil {
		return nil, err
	}

	redeemScript, witnessAddress, err := newWitnessRedeemScript(pubKeys,
		nRequire, massutil.AddressClassWitnessV0, &config.ChainParams)
	if err != nil {
		return nil, err
	}
	w.WitnessMap[witnessAddress.EncodeAddress()] = redeemScript
	pkScript, err := PayToBindingScriptHashScript(witnessAddress.ScriptAddress(), pocPkHash)
	if err != nil {
		return nil, err
	}
	return pkScript, nil
}

func (w *MockWallet) BuildStakingPkScript(nRequire, nTotal int, frozenPeriod uint64) ([]byte, error) {

	pubKeys, err := w.NewPublicKeys(nTotal)
	if err != nil {
		return nil, err
	}

	redeemScript, witnessAddress, err := newWitnessRedeemScript(pubKeys,
		nRequire, massutil.AddressClassWitnessStaking, &config.ChainParams)
	if err != nil {
		return nil, err
	}
	w.WitnessMap[witnessAddress.EncodeAddress()] = redeemScript
	pkScript, err := PayToStakingAddrScript(witnessAddress, frozenPeriod)
	if err != nil {
		return nil, err
	}
	return pkScript, nil
}

func (w *MockWallet) BuildP2WSHScript(nRequire, nTotal int) ([]byte, error) {

	pubKeys, err := w.NewPublicKeys(nTotal)
	if err != nil {
		return nil, err
	}

	redeemScript, witnessAddress, err := newWitnessRedeemScript(pubKeys, nRequire, massutil.AddressClassWitnessV0, &config.ChainParams)
	if err != nil {
		return nil, err
	}
	w.WitnessMap[witnessAddress.EncodeAddress()] = redeemScript
	pkScript, err := PayToAddrScript(witnessAddress)
	if err != nil {
		return nil, err
	}
	return pkScript, nil
}

func newWitnessRedeemScript(pubkeys []*btcec.PublicKey, nrequired int,
	addressClass uint16, net *config.Params) ([]byte, massutil.Address, error) {

	var addressPubKeyStructs []*massutil.AddressPubKey
	for i := 0; i < len(pubkeys); i++ {
		pubKeySerial := pubkeys[i].SerializeCompressed()
		addressPubKeyStruct, err := massutil.NewAddressPubKey(pubKeySerial, net)
		if err != nil {
			logging.CPrint(logging.ERROR, "create addressPubKey failed",
				logging.LogFormat{
					"err":       err,
					"version":   addressClass,
					"nrequired": nrequired,
				})
			return nil, nil, err
		}
		addressPubKeyStructs = append(addressPubKeyStructs, addressPubKeyStruct)
	}

	redeemScript, err := MultiSigScript(addressPubKeyStructs, nrequired)
	if err != nil {
		logging.CPrint(logging.ERROR, "create redeemScript failed",
			logging.LogFormat{
				"err":       err,
				"version":   addressClass,
				"nrequired": nrequired,
			})
		return nil, nil, err
	}
	var witAddress massutil.Address
	// scriptHash is witnessProgram
	scriptHash := sha256.Sum256(redeemScript)
	switch addressClass {
	case massutil.AddressClassWitnessStaking:
		witAddress, err = massutil.NewAddressStakingScriptHash(scriptHash[:], net)
	case massutil.AddressClassWitnessV0:
		witAddress, err = massutil.NewAddressWitnessScriptHash(scriptHash[:], net)
	default:
		return nil, nil, errors.New("invalid version")
	}

	if err != nil {
		logging.CPrint(logging.ERROR, "create witness address failed",
			logging.LogFormat{
				"err":       err,
				"version":   addressClass,
				"nrequired": nrequired,
			})
		return nil, nil, err
	}

	return redeemScript, witAddress, nil
}
