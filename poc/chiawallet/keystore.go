package chiawallet

import (
	"encoding/hex"
	"errors"
	"io/ioutil"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/massnetorg/mass-core/poc/chiapos"
)

var ErrMinerKeyNotExists = errors.New("miner key not exists")

type MinerKey struct {
	id               KeyID
	FarmerPrivateKey *chiapos.PrivateKey
	PoolPrivateKey   *chiapos.PrivateKey
	FarmerPublicKey  *chiapos.G1Element
	PoolPublicKey    *chiapos.G1Element
}

func (m *MinerKey) Encode() []byte {
	data := make([]byte, 2*chiapos.PrivateKeyBytes)
	copy(data, m.FarmerPrivateKey.Bytes())
	copy(data[chiapos.PrivateKeyBytes:], m.PoolPrivateKey.Bytes())
	return data
}

func (m *MinerKey) Decode(data []byte) error {
	if len(data) != 2*chiapos.PrivateKeyBytes {
		return errors.New("invalid length of MinerKey Bytes")
	}
	farmerPriv, err := chiapos.NewPrivateKeyFromBytes(data[:chiapos.PrivateKeyBytes])
	if err != nil {
		return err
	}
	farmerPub, err := farmerPriv.GetG1()
	if err != nil {
		return err
	}
	poolPriv, err := chiapos.NewPrivateKeyFromBytes(data[chiapos.PrivateKeyBytes:])
	if err != nil {
		return err
	}
	poolPub, err := poolPriv.GetG1()
	if err != nil {
		return err
	}
	m.FarmerPrivateKey, m.FarmerPublicKey = farmerPriv, farmerPub
	m.PoolPrivateKey, m.PoolPublicKey = poolPriv, poolPub
	m.id = NewKeyID(m.FarmerPublicKey, m.PoolPublicKey)
	return nil
}

func (m *MinerKey) Copy() *MinerKey {
	return &MinerKey{
		id:               m.id,
		FarmerPrivateKey: m.FarmerPrivateKey.Copy(),
		PoolPrivateKey:   m.PoolPrivateKey.Copy(),
		FarmerPublicKey:  m.FarmerPublicKey.Copy(),
		PoolPublicKey:    m.PoolPublicKey.Copy(),
	}
}

func (m *MinerKey) keyID() KeyID {
	if m.id == EmptyKeyID {
		m.id = NewKeyID(m.FarmerPublicKey, m.PoolPublicKey)
	}
	return m.id
}

type KeyID [2 * chiapos.PublicKeyBytes]byte

var EmptyKeyID KeyID

func NewKeyID(farmerPub, poolPub *chiapos.G1Element) KeyID {
	var id KeyID
	copy(id[:], farmerPub.Bytes())
	copy(id[chiapos.PublicKeyBytes:], poolPub.Bytes())
	return id
}

func (id KeyID) FarmerPublicKeyBytes() []byte {
	var bs [chiapos.PublicKeyBytes]byte
	copy(bs[:], id[:chiapos.PublicKeyBytes])
	return bs[:]
}

func (id KeyID) PoolPublicKeyBytes() []byte {
	var bs [chiapos.PublicKeyBytes]byte
	copy(bs[:], id[chiapos.PublicKeyBytes:])
	return bs[:]
}

func (id KeyID) String() string {
	return hex.EncodeToString(id[:])
}

func (id KeyID) Cmp(target KeyID) int {
	return strings.Compare(id.String(), target.String())
}

type Keystore struct {
	l    sync.RWMutex
	keys map[KeyID]*MinerKey
}

func NewEmptyKeystore() *Keystore {
	return &Keystore{
		keys: map[KeyID]*MinerKey{},
	}
}

func (store *Keystore) GetFarmerPrivateKey(pub *chiapos.G1Element) (*chiapos.PrivateKey, error) {
	store.l.RLock()
	defer store.l.RUnlock()
	pubStr := string(pub.Bytes())
	for id := range store.keys {
		if string(id.FarmerPublicKeyBytes()) == pubStr {
			return store.keys[id].FarmerPrivateKey.Copy(), nil
		}
	}
	return nil, ErrMinerKeyNotExists
}

func (store *Keystore) GetPoolPrivateKey(pub *chiapos.G1Element) (*chiapos.PrivateKey, error) {
	store.l.RLock()
	defer store.l.RUnlock()
	pubStr := string(pub.Bytes())
	for id := range store.keys {
		if string(id.PoolPublicKeyBytes()) == pubStr {
			return store.keys[id].PoolPrivateKey.Copy(), nil
		}
	}
	return nil, ErrMinerKeyNotExists
}

func (store *Keystore) GetMinerKeyByPoolPublicKey(pub *chiapos.G1Element) (*MinerKey, error) {
	store.l.RLock()
	defer store.l.RUnlock()
	pubStr := string(pub.Bytes())
	for id := range store.keys {
		if string(id.PoolPublicKeyBytes()) == pubStr {
			return store.keys[id].Copy(), nil
		}
	}
	return nil, ErrMinerKeyNotExists
}

func (store *Keystore) GetMinerKey(id KeyID) (*MinerKey, error) {
	store.l.RLock()
	defer store.l.RUnlock()
	key, ok := store.keys[id]
	if !ok {
		return nil, ErrMinerKeyNotExists
	}
	return key, nil
}

func (store *Keystore) SetMinerKey(farmerPriv, poolPriv *chiapos.PrivateKey) (KeyID, error) {
	store.l.Lock()
	defer store.l.Unlock()
	farmerPub, err := farmerPriv.GetG1()
	if err != nil {
		return KeyID{}, err
	}
	poolPub, err := poolPriv.GetG1()
	if err != nil {
		return KeyID{}, err
	}
	minerKey := &MinerKey{
		FarmerPrivateKey: farmerPriv.Copy(),
		PoolPrivateKey:   poolPriv.Copy(),
		FarmerPublicKey:  farmerPub,
		PoolPublicKey:    poolPub,
	}
	id := NewKeyID(farmerPub, poolPub)
	store.keys[id] = minerKey
	return id, nil
}

func (store *Keystore) GetAllMinerKeys() []*MinerKey {
	store.l.RLock()
	defer store.l.RUnlock()
	return store.getAllMinerKeys()
}

func (store *Keystore) ToStorage() *KeystoreStorage {
	store.l.RLock()
	defer store.l.RUnlock()
	keys := make(map[string]string, len(store.keys))
	for id := range store.keys {
		keys[hex.EncodeToString(id[:])] = hex.EncodeToString(store.keys[id].Encode())
	}
	return &KeystoreStorage{Keys: keys}
}

func (store *Keystore) FromStorage(storage *KeystoreStorage) error {
	store.l.Lock()
	defer store.l.Unlock()
	keys := make(map[KeyID]*MinerKey, len(storage.Keys))
	for id := range storage.Keys {
		data, err := hex.DecodeString(storage.Keys[id])
		if err != nil {
			return err
		}
		m := &MinerKey{}
		if err = m.Decode(data); err != nil {
			return err
		}
		keys[NewKeyID(m.FarmerPublicKey, m.PoolPublicKey)] = m
	}
	store.keys = keys
	return nil
}

func NewKeystoreFromFile(filename string) (*Keystore, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return &Keystore{keys: map[KeyID]*MinerKey{}}, nil
	}
	storage := &KeystoreStorage{}
	if err = storage.FromBytes(data); err != nil {
		return nil, err
	}
	store := &Keystore{}
	if err = store.FromStorage(storage); err != nil {
		return nil, err
	}
	return store, nil
}

func WriteKeystoreToFile(store *Keystore, filename string, perm os.FileMode) error {
	data, err := store.ToStorage().Bytes()
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filename, data, perm)
}

func (store *Keystore) getAllMinerKeys() []*MinerKey {
	var keys []*MinerKey
	for id := range store.keys {
		keys = append(keys, store.keys[id].Copy())
	}
	sort.SliceStable(keys, func(i, j int) bool {
		return keys[i].keyID().Cmp(keys[j].keyID()) < 0
	})
	return keys
}
