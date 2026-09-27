package store

import "time"

const FormatVersion = 1

type ShardRef struct {
	ID    string `json:"id"`
	Index int    `json:"index"`
	Size  int    `json:"size"`
}

type ChunkManifest struct {
	Index int `json:"index"`
	// CipherLength is the exact number of stored bytes in this chunk before
	// Reed-Solomon padding, so reassembly can trim back to it.
	CipherLength int        `json:"cipher_length"`
	ShardSize    int        `json:"shard_size"`
	Shards       []ShardRef `json:"shards"`
}

// Manifest describes an object as opaque, content-addressed, Reed-Solomon shards.
// The node no longer encrypts objects: content arrives already encrypted by the
// coordinator (see backend/services/content_keys.py), so a node holds ciphertext
// it cannot read and there is no per-object key here to wrap. PlainSHA256 is the
// digest of the STORED (ciphertext) bytes, kept as an end-to-end integrity check.
type Manifest struct {
	Version      int             `json:"version"`
	ObjectID     string          `json:"object_id"`
	Bucket       string          `json:"bucket"`
	Key          string          `json:"key"`
	ContentType  string          `json:"content_type"`
	PlainSize    int64           `json:"plain_size"`
	PlainSHA256  string          `json:"plain_sha256"`
	DataShards   int             `json:"data_shards"`
	ParityShards int             `json:"parity_shards"`
	ChunkBytes   int             `json:"chunk_bytes"`
	Chunks       []ChunkManifest `json:"chunks"`
	CreatedAt    time.Time       `json:"created_at"`
}

type StoredItem struct {
	Kind        string    `json:"kind"`
	ID          string    `json:"id"`
	DisplayName string    `json:"display_name"`
	ContentType string    `json:"content_type,omitempty"`
	Size        int64     `json:"size"`
	LocalObject bool      `json:"local_object"`
	Rejected    bool      `json:"rejected"`
	CreatedAt   time.Time `json:"created_at"`
}

type RemoteShard struct {
	ID        string    `json:"id"`
	ObjectID  string    `json:"object_id"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
}
