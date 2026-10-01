package dcs

import "crypto/rand"

// randRead is crypto/rand.Read, indirected so record.go stays testable and so
// the single import of crypto/rand for entropy lives in one place.
var randRead = rand.Read
