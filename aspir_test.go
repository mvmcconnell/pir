package pir

import (
	"math/rand"
	"testing"

	"github.com/sachaservan/paillier"
)

// run with 'go test -v -run TestASPIR' to see log outputs.
func TestASPIR(t *testing.T) {
	setup()

	secparam := StatisticalSecurityParam // statistical secuirity parameter for proof soundness
	nprocs := 1

	sk, pk := paillier.KeyGen(128)

	keydb := GenerateRandomDB(TestDBSize, int(secparam/4)) // get secparam in bytes
	dimWidth, dimHeight := keydb.GetDimentionsForDatabase(TestDBHeight, 1)

	for i := 0; i < NumQueries; i++ {
		qRowIndex := rand.Intn(dimHeight)
		qColIndex := rand.Intn(dimWidth) // this is the "group number" in the row

		// generate auth token consisiting of double encryption of the key
		authKey := keydb.Slots[qRowIndex*dimWidth+qColIndex]
		authToken := AuthTokenForKey(pk, authKey)

		query := keydb.NewDoublyEncryptedQuery(pk, dimWidth, dimHeight, 1, qRowIndex, qColIndex)

		// issue challenge
		chalToken, err := AuthChalForQuery(secparam, keydb, query, authToken, nprocs)
		if err != nil {
			t.Fatal(err)
		}

		// generate proof
		proofToken, err := AuthProve(sk, chalToken)
		if err != nil {
			t.Fatal(err)
		}

		// generate proof
		ok := AuthCheck(pk, chalToken, proofToken)
		if !ok {
			t.Fatalf("ASPIR proof failed")
		}

	}
}

// run with 'go test -v -run TestSharedASPIR' to see log outputs.
func TestSharedASPIR(t *testing.T) {
	setup()

	secparam := StatisticalSecurityParam // statistical secuirity parameter for proof soundness

	keydb := GenerateRandomDB(TestDBSize, int(secparam/4)) // get secparam in bytes

	for i := 0; i < NumQueries; i++ {
		index := uint(rand.Intn(TestDBSize))

		// generate auth token consisiting of double encryption of the key
		authKey := keydb.Slots[index]
		authTokenShares := AuthTokenSharesForKey(authKey, 2)
		queryShares := keydb.NewIndexQueryShares(index, 1, 2)

		audits := make([]*AuditTokenShare, 2)
		audits[0], _ = GenerateAuditForSharedQuery(keydb, queryShares[0], authTokenShares[0], 1)
		audits[1], _ = GenerateAuditForSharedQuery(keydb, queryShares[1], authTokenShares[1], 1)

		// generate proof
		ok := CheckAudit(audits...)
		if !ok {
			t.Fatalf("Secret shared ASPIR proof failed")
		}

	}

}

func BenchmarkChallenge(b *testing.B) {
	setup()

	secparam := StatisticalSecurityParam // statistical secuirity parameter for proof soundness

	_, pk := paillier.KeyGen(1024)
	keydb := GenerateRandomDB(BenchmarkDBSize, int(secparam/4))
	dimWidth, dimHeight := keydb.GetDimentionsForDatabase(BenchmarkDBHeight, 1)

	// generate auth token consisiting of double encryption of the key
	authKey := keydb.Slots[0]
	authToken := AuthTokenForKey(pk, authKey)

	query := keydb.NewDoublyEncryptedQuery(pk, dimWidth, dimHeight, 1, 0, 0)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := AuthChalForQuery(secparam, keydb, query, authToken, 1)

		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkProve(b *testing.B) {
	setup()

	secparam := StatisticalSecurityParam // statistical secuirity parameter for proof soundness

	sk, pk := paillier.KeyGen(1024)
	keydb := GenerateRandomDB(BenchmarkDBSize, int(secparam/4))
	dimWidth, dimHeight := keydb.GetDimentionsForDatabase(BenchmarkDBHeight, 1)

	// generate auth token consisiting of double encryption of the key
	authKey := keydb.Slots[0]
	authToken := AuthTokenForKey(pk, authKey)

	query := keydb.NewDoublyEncryptedQuery(pk, dimWidth, dimHeight, 1, 0, 0)
	chalToken, _ := AuthChalForQuery(secparam, keydb, query, authToken, 1)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := AuthProve(sk, chalToken)

		if err != nil {
			panic(err)
		}
	}
}
