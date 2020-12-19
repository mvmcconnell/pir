package aspir

import (
	"bytes"
	"crypto/sha256"
	"math/rand"

	"github.com/ncw/gmp"
)

// ROCommitment is a hiding and binding commitment
// consisting of a random oracle hash of the
// commited value
type ROCommitment struct {
	HashBytes []byte
	R         *gmp.Int
}

// Commit uses the random oracle to generate a commitment
func Commit(value *gmp.Int) *ROCommitment {
	rBytes := make([]byte, 32)
	rand.Read(rBytes)
	r := new(gmp.Int).SetBytes(rBytes)
	comm := &ROCommitment{
		HashBytes: RandomOracleDigest(value, r),
		R:         r,
	}

	return comm
}

// CheckOpen returns true if the commitment opening is valid
func (c *ROCommitment) CheckOpen(value *gmp.Int) bool {
	hash1 := RandomOracleDigest(value, c.R)
	hash2 := c.HashBytes

	return bytes.Equal(hash1, hash2)
}

// RandomOracleDigest returns the digest of all the input bytes
// using SHA 256 to model a random oracle
func RandomOracleDigest(values ...*gmp.Int) []byte {

	hashData := make([]byte, 0)
	for i, b := range values {
		if i == 0 {
			continue
		}
		hashData = append(hashData, b.Bytes()...)
	}

	res := sha256.Sum256(hashData)
	return res[:]
}
