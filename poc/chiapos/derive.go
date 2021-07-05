package chiapos

func AugDerivePath(master *PrivateKey, paths []int) (key *PrivateKey, err error) {
	key = master
	s := NewAugSchemeMPL()
	for _, index := range paths {
		if key, err = s.DeriveChildSk(key, index); err != nil {
			return nil, err
		}
	}
	return
}

func MasterSkToFarmerSk(master *PrivateKey) (*PrivateKey, error) {
	return AugDerivePath(master, []int{12381, 8444, 0, 0})
}

func MasterSkToPoolSk(master *PrivateKey) (*PrivateKey, error) {
	return AugDerivePath(master, []int{12381, 8444, 1, 0})
}

func MasterSkToLocalSk(master *PrivateKey) (*PrivateKey, error) {
	return AugDerivePath(master, []int{12381, 8444, 3, 0})
}
