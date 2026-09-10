package gateway

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// FileIdentity is a lightweight probe signer. It uses the same persistent
// libp2p Ed25519 key format as a full node without starting storage, I2P, or a
// DHT. Probe results are returned directly to candidates, so probes do not need
// storage-node networking.
type FileIdentity struct {
	key crypto.PrivKey
	id  peer.ID
}

func LoadOrCreateFileIdentity(dataDir string) (*FileIdentity, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(dataDir, "p2p.key")
	raw, err := os.ReadFile(path)
	var key crypto.PrivKey
	if err == nil {
		key, err = crypto.UnmarshalPrivateKey(raw)
	} else if errors.Is(err, os.ErrNotExist) {
		key, _, err = crypto.GenerateEd25519Key(nil)
		if err == nil {
			raw, err = crypto.MarshalPrivateKey(key)
		}
		if err == nil {
			err = os.WriteFile(path, raw, 0600)
		}
	}
	if err != nil {
		return nil, err
	}
	id, err := peer.IDFromPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &FileIdentity{key: key, id: id}, nil
}

func (i *FileIdentity) ID() string { return i.id.String() }

func (i *FileIdentity) Sign(message []byte) ([]byte, error) {
	return i.key.Sign(message)
}

func (i *FileIdentity) PublicKey() ([]byte, error) {
	return crypto.MarshalPublicKey(i.key.GetPublic())
}

// Probe readiness is local listener readiness. A probe returns signed results
// directly and does not publish DHT values of its own.
func (i *FileIdentity) DHTReady() bool { return true }
