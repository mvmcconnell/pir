package aspir

import (
	"errors"
	"fmt"
	"math/rand"

	"github.com/sachaservan/pir"

	"github.com/ncw/gmp"
	"github.com/sachaservan/paillier"
)

/*
 Single-server AHE variant of ASPIR
*/

// AuthenticatedEncryptedQuery is a single-server encrypted query
// attached with an authentication token that proves knowledge of a
// secret associated with the retrieved item.
// Either Query0 or Query1`is a "null" query that doesn't retrieve
// any value. It is needed to prevent the server from generating
// a ''tagged'' key database in an attempt to learn which item
// is being retrieved by the client ...
type AuthenticatedEncryptedQuery struct {
	Query0     *pir.DoublyEncryptedQuery
	Query1     *pir.DoublyEncryptedQuery
	AuthToken0 *paillier.Ciphertext
	AuthToken1 *paillier.Ciphertext
}

// ChalToken is the challenge issued to the client
// in order to prove knowledge of the key associated with the retrieved item
type ChalToken struct {
	Token0   *paillier.Ciphertext
	Token1   *paillier.Ciphertext
	SecParam int
}

// ProofToken is the response provided by the client to a ChalToken
type ProofToken struct {
	T    *paillier.Ciphertext
	P    *paillier.DDLEQProof
	QBit int
	R    *gmp.Int
	S    *gmp.Int
}

// GenerateAuthenticatedQuery generates an authenticated PIR query that can be verified by the server
func GenerateAuthenticatedQuery(dbmd *pir.DBMetadata, pk *paillier.PublicKey, groupSize, index int, authKey *pir.Slot) (*AuthenticatedEncryptedQuery, int) {

	queryReal := dbmd.NewDoublyEncryptedQuery(pk, groupSize, -1)
	queryFake := dbmd.NewDoublyEncryptedQuery(pk, groupSize, -1)

	fakeToken := pk.EncryptZero()
	realToken := pk.EncryptZero()

	var query0 *pir.DoublyEncryptedQuery
	var query1 *pir.DoublyEncryptedQuery
	var token0 *paillier.Ciphertext
	var token1 *paillier.Ciphertext

	bit := rand.Intn(2)
	if bit == 0 {
		query0 = queryReal
		token0 = realToken
		query1 = queryFake
		token1 = fakeToken
	} else {
		query0 = queryFake
		token0 = fakeToken
		query1 = queryReal
		token1 = realToken
	}

	authQuery := &AuthenticatedEncryptedQuery{
		Query0:     query0,
		Query1:     query1,
		AuthToken0: token0,
		AuthToken1: token1,
	}

	return authQuery, bit
}

// AuthChalForQuery generates a challenge token for the provided PIR query
func AuthChalForQuery(
	secparam int,
	keyDB *pir.Database,
	query *AuthenticatedEncryptedQuery,
	nprocs int) (*ChalToken, error) {

	// get the row for query0
	rowQueryRes0, err := keyDB.PrivateEncryptedQuery(query.Query0.Row, nprocs)
	if err != nil {
		return nil, err
	}

	// get the row for query0
	rowQueryRes1, err := keyDB.PrivateEncryptedQuery(query.Query1.Row, nprocs)
	if err != nil {
		return nil, err
	}

	res0, err := keyDB.PrivateEncryptedQueryOverEncryptedResult(query.Query0.Col, rowQueryRes0, nprocs)
	if err != nil {
		return nil, err
	}

	res1, err := keyDB.PrivateEncryptedQueryOverEncryptedResult(query.Query1.Col, rowQueryRes1, nprocs)
	if err != nil {
		return nil, err
	}

	chalTokenValue0 := query.Query0.Row.Pk.NestedSub(res0.Slots[0].Cts[0], query.AuthToken0)
	chalTokenValue1 := query.Query1.Row.Pk.NestedSub(res1.Slots[0].Cts[0], query.AuthToken1)

	return &ChalToken{chalTokenValue0, chalTokenValue1, secparam}, nil
}

// AuthProve proves that challenge token is correct (a nested encryption of zero)
// bit indicate which query (query0 or query1) is the real query
func AuthProve(sk *paillier.SecretKey, bit int, chalToken *ChalToken) (*ProofToken, error) {

	zero := gmp.NewInt(0)
	decTok0 := sk.NestedDecrypt(chalToken.Token0)
	decTok1 := sk.NestedDecrypt(chalToken.Token1)

	fmt.Printf("token0 %v\n", decTok0)
	fmt.Printf("token1 %v\n", decTok1)

	if decTok0.Cmp(zero) != 0 && decTok1.Cmp(zero) != 0 {
		return nil, errors.New("both tokens non-zero -- server likely cheating")
	}

	var chal *paillier.Ciphertext
	var queryBit = bit

	// if one of the tokens is non-zero then the server cheated
	// therefore, we must prove whichever token is zero
	// to avoid leaking information about the original query
	if decTok0.Cmp(zero) != 0 || decTok1.Cmp(zero) != 0 {
		if decTok0.Cmp(zero) == 0 {
			chal = chalToken.Token0
			queryBit = 0
		} else {
			chal = chalToken.Token1
			queryBit = 1
		}
	} else {
		if bit == 0 {
			chal = chalToken.Token0
			queryBit = 0
		} else {
			chal = chalToken.Token1
			queryBit = 1
		}
	}

	chal2, a, b := sk.NestedRandomize(chal)

	proof, err := sk.ProveDDLEQ(chalToken.SecParam, chal, chal2, a, b)

	if err != nil {
		return nil, err
	}

	// extract the randomness from the nested ciphertext
	// to prove that ct2 is an encryption of zero
	s := sk.ExtractRandonness(chal2)
	ctInner := sk.DecryptNestedCiphertextLayer(chal2)
	r := sk.ExtractRandonness(ctInner)

	return &ProofToken{chal2, proof, queryBit, r, s}, nil
}

// AuthCheck verifies the proof provided by the client and outputs True if and only if the proof is valid
func AuthCheck(pk *paillier.PublicKey, chalToken *ChalToken, proofToken *ProofToken) bool {

	var ct1 *paillier.Ciphertext
	if proofToken.QBit == 0 {
		ct1 = chalToken.Token0
	} else {
		ct1 = chalToken.Token1
	}

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
