package aspir

import (
	"errors"

	"github.com/sachaservan/pir"

	"github.com/ncw/gmp"
	"github.com/sachaservan/paillier"
)

/*
 Single-server AHE variant of ASPIR
*/

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
func AuthTokenForKey(pk *paillier.PublicKey, authKey *pir.Slot) *AuthToken {
	authKeyInt := new(gmp.Int).SetBytes(authKey.Data)
	authToken := &AuthToken{}
	authToken.T = pk.Encrypt(authKeyInt)

	return authToken
}

// AuthChalForQuery generates a challenge token for the provided PIR query
func AuthChalForQuery(
	secparam int,
	keyDB *pir.Database,
	query *pir.DoublyEncryptedQuery,
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

/*
 Secret shared DPF variant of ASPIR
*/

// AuditTokenShare is a secret share of an audit token
// used to authenticate two-server PIR queries
type AuditTokenShare struct {
	T *pir.Slot
}

// AuthTokenShare is a share of the key associated with the queried item
type AuthTokenShare struct {
	T *pir.Slot
}

// AuthTokenSharesForKey generates auth token shares for a specific AuthKey (encoded as a slot)
func AuthTokenSharesForKey(authKey *pir.Slot, numShares int) []*AuthTokenShare {

	numBytes := len(authKey.Data)
	shares := make([]*AuthTokenShare, numShares)
	accumulator := pir.NewEmptySlot(numBytes)

	for i := 1; i < numShares; i++ {
		share := pir.NewRandomSlot(numBytes)
		pir.XorSlots(accumulator, share)
		shares[i] = &AuthTokenShare{share}
	}

	pir.XorSlots(accumulator, authKey)
	shares[0] = &AuthTokenShare{accumulator}

	return shares
}

// GenerateAuditForSharedQuery generates an audit share that is sent to the other server(s)
func GenerateAuditForSharedQuery(
	keyDB *pir.Database,
	query *pir.QueryShare,
	authToken *AuthTokenShare,
	nprocs int) (*AuditTokenShare, error) {

	res, err := keyDB.PrivateSecretSharedQuery(query, nprocs)
	if err != nil {
		return nil, err
	}

	if len(res.Shares) != 1 {
		return nil, errors.New("Invalid challenge ciphertext result")
	}

	keySlotShare := res.Shares[0]
	pir.XorSlots(keySlotShare, authToken.T)
	return &AuditTokenShare{keySlotShare}, nil
}

// CheckAudit outputs True of all provided audit tokens xor to zero
func CheckAudit(auditTokens ...*AuditTokenShare) bool {

	res := pir.NewEmptySlot(len(auditTokens[0].T.Data))
	for _, tok := range auditTokens {
		pir.XorSlots(res, tok.T)
	}

	// make sure the resulting slot is all zero
	if ints, _, _ := res.ToGmpIntArray(1); ints[0].Cmp(gmp.NewInt(0)) != 0 {
		return false
	}

	return true
}
