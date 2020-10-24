package pir

import (
	"math/rand"
	"testing"
	"time"

	"github.com/sachaservan/paillier"
)

// test configuration parameters
const DBHeight = 1 << 5
const DBWidth = 1 << 5

const SlotBytes = 20
const SlotBytesStep = 5
const NumProcsForQuery = 4 // number of parallel processors
const NumQueries = 50      // number of queries to run

func setup() {
	rand.Seed(time.Now().Unix())
}

// run with 'go test -v -run TestSharedQuery' to see log outputs.
func TestSharedQuery(t *testing.T) {
	setup()

	db := GenerateRandomDB(DBWidth, DBHeight, SlotBytes)

	for i := 0; i < NumQueries; i++ {
		qIndex := uint(rand.Intn(DBHeight))

		shares := db.NewIndexQueryShares(qIndex, 2)

		resA, err := db.PrivateSecretSharedQuery(shares[0], NumProcsForQuery)
		if err != nil {
			t.Fatalf("%v", err)
		}

		resB, err := db.PrivateSecretSharedQuery(shares[1], NumProcsForQuery)
		if err != nil {
			t.Fatalf("%v", err)
		}

		resultShares := [...]*SecretSharedQueryResult{resA, resB}
		res := Recover(resultShares[:])

		for j := 0; j < db.Width; j++ {
			if !db.Slots[qIndex][j].Equal(res[j]) {
				t.Fatalf(
					"Query result is incorrect. %v != %v\n",
					db.Slots[qIndex][j],
					res[j],
				)
			}

			t.Logf("Slot %v, is %v\n", j, res[j])
		}
	}
}

// run with 'go test -v -run TestEncryptedQuery' to see log outputs.
func TestEncryptedQuery(t *testing.T) {
	setup()

	sk, pk := paillier.KeyGen(512)

	for slotBytes := 1; slotBytes < SlotBytes; slotBytes += SlotBytesStep {
		db := GenerateRandomDB(DBWidth, DBHeight, SlotBytes)

		for i := 0; i < NumQueries; i++ {
			qIndex := rand.Intn(DBHeight)

			query := db.NewEncryptedQuery(pk, qIndex)
			response, err := db.PrivateEncryptedQuery(query, NumProcsForQuery)
			if err != nil {
				t.Fatalf("%v", err)
			}

			res := RecoverEncrypted(response, sk)

			for j := 0; j < db.Width; j++ {
				if !db.Slots[qIndex][j].Equal(res[j]) {
					t.Fatalf(
						"Query result is incorrect. %v != %v\n",
						db.Slots[qIndex][j],
						res[j],
					)
				}
			}
		}
	}
}

// run with 'go test -v -run TestDoublyEncryptedQuery' to see log outputs.
func TestDoublyEncryptedQuery(t *testing.T) {
	setup()

	sk, pk := paillier.KeyGen(512)

	for slotBytes := 1; slotBytes < SlotBytes; slotBytes += SlotBytesStep {
		db := GenerateRandomDB(DBWidth, DBHeight, SlotBytes)

		for i := 0; i < NumQueries; i++ {
			qRowIndex := rand.Intn(DBHeight)
			qColIndex := rand.Intn(DBWidth)

			query := db.NewDoublyEncryptedQuery(pk, qRowIndex, qColIndex)
			response, err := db.PrivateDoublyEncryptedQuery(query, NumProcsForQuery)
			if err != nil {
				t.Fatalf("%v", err)
			}

			res := RecoverDoublyEncrypted(response, sk)

			if !db.Slots[qRowIndex][qColIndex].Equal(res) {
				t.Fatalf(
					"Query result is incorrect. %v != %v\n",
					db.Slots[qRowIndex][qColIndex],
					res,
				)
			}

		}
	}
}

func BenchmarkBuildDB(b *testing.B) {
	setup()

	// benchmark index build time
	for i := 0; i < b.N; i++ {
		GenerateRandomDB(DBWidth, DBHeight, SlotBytes)
	}
}

func BenchmarkQuerySecretShares(b *testing.B) {
	setup()

	db := GenerateRandomDB(DBWidth, DBHeight, SlotBytes)
	queryA := db.NewIndexQueryShares(0, 2)[0]

	b.ResetTimer()

	// benchmark index build time
	for i := 0; i < b.N; i++ {
		_, err := db.PrivateSecretSharedQuery(queryA, NumProcsForQuery)
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkQuerySecretSharesSingleThread(b *testing.B) {
	setup()

	db := GenerateRandomDB(DBWidth, DBHeight, SlotBytes)
	queryA := db.NewIndexQueryShares(0, 2)[0]

	b.ResetTimer()

	// benchmark index build time
	for i := 0; i < b.N; i++ {
		_, err := db.PrivateSecretSharedQuery(queryA, 1)
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkQuerySecretSharesSingle8Thread(b *testing.B) {
	setup()

	db := GenerateRandomDB(DBWidth, DBHeight, SlotBytes)
	queryA := db.NewIndexQueryShares(0, 2)[0]

	b.ResetTimer()

	// benchmark index build time
	for i := 0; i < b.N; i++ {
		_, err := db.PrivateSecretSharedQuery(queryA, 8)
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkEncryptedQueryAHESingleThread(b *testing.B) {
	setup()

	_, pk := paillier.KeyGen(1024)
	db := GenerateRandomDB(DBWidth, DBHeight, SlotBytes)
	query := db.NewEncryptedQuery(pk, 0)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := db.PrivateEncryptedQuery(query, 1)

		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkEncryptedQueryAHE8Thread(b *testing.B) {
	setup()

	_, pk := paillier.KeyGen(1024)
	db := GenerateRandomDB(DBWidth, DBHeight, SlotBytes)
	query := db.NewEncryptedQuery(pk, 0)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := db.PrivateEncryptedQuery(query, 8)

		if err != nil {
			panic(err)
		}
	}
}
