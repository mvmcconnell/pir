package pir

import (
	"errors"

	"github.com/ncw/gmp"
	"github.com/sachaservan/paillier"
)

// AuthToken is provided by the client to prove knowledge of the
// access key associated with the retrieved item
type AuthToken struct {
	T *paillier.Ciphertext
}

// ChalToken is the challenge issued to the client
// in order to prove knowledge of the key associated with the retrieved item
type ChalToken struct {
	T        *paillier.Ciphertext
	SecParam int
}

// ProofToken is the response provided by the client to a ChalToken
type ProofToken struct {
	T *paillier.Ciphertext
	P *paillier.DDLEQProof
	R *gmp.Int
	S *gmp.Int
}

// AuthTokenForKey generates an auth token for a specific AuthKey (encoded as a slot)
func AuthTokenForKey(pk *paillier.PublicKey, authKey *Slot) *AuthToken {
	authKeyInt := new(gmp.Int).SetBytes(authKey.Data)
	authToken := &AuthToken{}
	authToken.T = pk.Encrypt(authKeyInt)

	return authToken
}

// AuthChalForQuery generates a challenge token for the provided PIR query
func AuthChalForQuery(
	secparam int,
	keyDB *Database,
	query *DoublyEncryptedQuery,
	authToken *AuthToken,
	nprocs int) (*ChalToken, error) {

	res, err := keyDB.PrivateDoublyEncryptedQuery(query, nprocs)
	if err != nil {
		return nil, err
	}

	if len(res.Slots) != 1 || len(res.Slots[0].Cts) != 1 {
		return nil, errors.New("Invalid challenge ciphertext result")
	}

	chalTokenValue := query.Pk.NestedSub(res.Slots[0].Cts[0], authToken.T)

	return &ChalToken{chalTokenValue, secparam}, nil
}

// AuthProve proves that challenge token is correct (a nested encryption of zero)
func AuthProve(sk *paillier.SecretKey, chalToken *ChalToken) (*ProofToken, error) {

	if sk.NestedDecrypt(chalToken.T).Cmp(gmp.NewInt(0)) != 0 {
		panic("chal token is not zero")
	}

	ct1 := chalToken.T
	ct2, a, b := sk.NestedRandomize(ct1)

	proof, err := sk.ProveDDLEQ(chalToken.SecParam, ct1, ct2, a, b)

	if err != nil {
		return nil, err
	}

	// extract the randomness from the nested ciphertext
	// to prove that ct2 is an encryption of zero
	s := sk.ExtractRandonness(ct2)
	ctInner := sk.DecryptNestedCiphertextLayer(ct2)
	r := sk.ExtractRandonness(ctInner)

	return &ProofToken{ct2, proof, r, s}, nil
}

// AuthCheck verifies the proof provided by the client and outputs True if and only if the proof is valid
func AuthCheck(pk *paillier.PublicKey, chalToken *ChalToken, proofToken *ProofToken) bool {

	ct1 := chalToken.T
	ct2 := proofToken.T

	// make sure that ct2 is a re-encryption of ct1
	if !pk.VerifyDDLEQProof(ct1, ct2, proofToken.P) {
		return false
	}

	// check that ct2 is an encryption of 0 ==> ct1 is an encryption of 0
	// perform a double encryption of zero with provided randomness
	check := pk.EncryptWithRAtLevel(gmp.NewInt(0), proofToken.R, paillier.EncLevelOne)
	check = pk.EncryptWithRAtLevel(check.C, proofToken.S, paillier.EncLevelTwo)

	if check.C.Cmp(ct2.C) != 0 {
		return false
	}

	return true
}
