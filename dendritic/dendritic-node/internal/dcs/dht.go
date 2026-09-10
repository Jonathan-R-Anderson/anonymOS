package dcs

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// WorkerDHTValidator validates and selects dcs_worker records in the DHT,
// mirroring gateway.DHTValidator. A record is valid only if it is well-formed,
// unexpired, stored under its own node's key, and signed by that node's key --
// so a peer cannot advertise capacity on someone else's behalf. Select prefers
// the highest Sequence, so a stale cached record never wins over a fresh one.
type WorkerDHTValidator struct {
	Now func() time.Time
}

func (v WorkerDHTValidator) Validate(key string, value []byte) error {
	nodeID, ok := workerDHTNodeID(key)
	if !ok {
		return errors.New("dcs: invalid worker DHT key")
	}
	var rec WorkerRecord
	if len(value) > 64<<10 || json.Unmarshal(value, &rec) != nil {
		return errors.New("dcs: invalid worker record encoding")
	}
	if rec.RecordType != "dcs_worker" || rec.NodeID != nodeID {
		return errors.New("dcs: worker record stored under the wrong key")
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	if rec.ExpiresAt <= now.Unix() || rec.ExpiresAt-rec.IssuedAt > 3600 {
		return errors.New("dcs: worker record expired or over-long")
	}
	return verifyWorkerSignature(rec)
}

func (v WorkerDHTValidator) Select(_ string, values [][]byte) (int, error) {
	best, bestSeq := -1, uint64(0)
	for i, value := range values {
		var rec WorkerRecord
		if json.Unmarshal(value, &rec) != nil {
			continue
		}
		if best == -1 || rec.Sequence > bestSeq {
			best, bestSeq = i, rec.Sequence
		}
	}
	if best < 0 {
		return 0, errors.New("dcs: no valid worker records")
	}
	return best, nil
}

func workerDHTNodeID(key string) (string, bool) {
	prefix := "/" + DHTWorkerNamespace + "/"
	if !strings.HasPrefix(key, prefix) {
		return "", false
	}
	return strings.TrimPrefix(key, prefix), true
}

// SignWorkerRecord fills PublicKey and Signature over the record's other fields.
func SignWorkerRecord(signer EnvelopeSigner, rec WorkerRecord) (WorkerRecord, error) {
	key, err := signer.PublicKey()
	if err != nil {
		return rec, err
	}
	rec.NodeID = signer.ID()
	rec.PublicKey = base64.RawStdEncoding.EncodeToString(key)
	rec.Signature = ""
	body, err := json.Marshal(rec)
	if err != nil {
		return rec, err
	}
	sig, err := signer.Sign(body)
	if err != nil {
		return rec, err
	}
	rec.Signature = base64.RawStdEncoding.EncodeToString(sig)
	return rec, nil
}

func verifyWorkerSignature(rec WorkerRecord) error {
	rawKey, err := base64.RawStdEncoding.DecodeString(rec.PublicKey)
	if err != nil {
		return errors.New("dcs: invalid worker public key")
	}
	key, err := crypto.UnmarshalPublicKey(rawKey)
	if err != nil {
		return errors.New("dcs: invalid worker public key")
	}
	id, err := peer.IDFromPublicKey(key)
	if err != nil || id.String() != rec.NodeID {
		return errors.New("dcs: worker key does not match node id")
	}
	rawSig, err := base64.RawStdEncoding.DecodeString(rec.Signature)
	if err != nil {
		return errors.New("dcs: invalid worker signature")
	}
	unsigned := rec
	unsigned.Signature = ""
	body, err := json.Marshal(unsigned)
	if err != nil {
		return err
	}
	ok, err := key.Verify(body, rawSig)
	if err != nil || !ok {
		return errors.New("dcs: invalid worker signature")
	}
	return nil
}
