package pir

import (
	"math"
	"math/rand"
	"testing"
	"time"

	"github.com/sachaservan/paillier"
)

func setup() {
	rand.Seed(time.Now().Unix())
}

// run with 'go test -v -run TestSharedQuery' to see log outputs.
func TestSharedQuery(t *testing.T) {
	setup()

	db := GenerateRandomDB(TestDBSize, SlotBytes)

	for groupSize := MinGroupSize; groupSize < MaxGroupSize; groupSize++ {

		dimWidth := groupSize
		dimHeight := int(math.Ceil(float64(TestDBSize / dimWidth)))

		for i := 0; i < NumQueries; i++ {
			qIndex := uint(rand.Intn(dimHeight))
			shares := db.NewIndexQueryShares(qIndex, groupSize, 2)

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

			for j := 0; j < dimWidth; j++ {

				index := int(qIndex)*dimWidth + j
				if index >= db.DBSize {
					break
				}

				if !db.Slots[index].Equal(res[j]) {
					t.Fatalf(
						"Query result is incorrect. %v != %v\n",
						db.Slots[index],
						res[j],
					)
				}

				t.Logf("Slot %v, is %v\n", j, res[j])
			}
		}
	}
}

// run with 'go test -v -run TestEncryptedQuery' to see log outputs.
func TestEncryptedQuery(t *testing.T) {
	setup()

	sk, pk := paillier.KeyGen(128)

	for slotBytes := 1; slotBytes < SlotBytes; slotBytes += SlotBytesStep {
		db := GenerateRandomDB(TestDBSize, SlotBytes)

		for groupSize := MinGroupSize; groupSize < MaxGroupSize; groupSize++ {

			dimWidth, dimHeight := db.GetDimentionsForDatabase(TestDBHeight, groupSize)

			for i := 0; i < NumQueries; i++ {
				qIndex := rand.Intn(dimHeight)

				query := db.NewEncryptedQuery(pk, dimHeight, dimWidth, groupSize, qIndex)

				response, err := db.PrivateEncryptedQuery(query, NumProcsForQuery)
				if err != nil {
					t.Fatalf("%v", err)
				}

				res := RecoverEncrypted(response, sk)

				if len(res)%groupSize != 0 {
					t.Fatalf("Response size is not a multiple of DBGroupSize")
				}

				for j := 0; j < dimWidth; j++ {

					index := int(qIndex)*dimWidth + j
					if index >= db.DBSize {
						break
					}

					if !db.Slots[index].Equal(res[j]) {
						t.Fatalf(
							"Query result is incorrect. %v != %v\n",
							db.Slots[index],
							res[j],
						)
					}
				}
			}
		}
	}
}

// run with 'go test -v -run TestDoublyEncryptedQuery' to see log outputs.
func TestDoublyEncryptedQuery(t *testing.T) {
	setup()

	sk, pk := paillier.KeyGen(128)

	for slotBytes := 1; slotBytes < SlotBytes; slotBytes += SlotBytesStep {
		db := GenerateRandomDB(TestDBSize, SlotBytes)

		for groupSize := MinGroupSize; groupSize < MaxGroupSize; groupSize++ {

			dimWidth, dimHeight := db.GetDimentionsForDatabase(TestDBHeight, groupSize)

			for i := 0; i < NumQueries; i++ {
				qRowIndex := rand.Intn(dimHeight)
				qColIndex := rand.Intn(dimWidth) // this is the "group number" in the row

				query := db.NewDoublyEncryptedQuery(pk, dimWidth, dimHeight, groupSize, qRowIndex, qColIndex)
				response, err := db.PrivateDoublyEncryptedQuery(query, NumProcsForQuery)
				if err != nil {
					t.Fatalf("%v", err)
				}

				res := RecoverDoublyEncrypted(response, sk)

				for col := 0; col < groupSize; col++ {

					index := int(qRowIndex*dimWidth*groupSize + qColIndex*groupSize + col)
					if index >= db.DBSize {
						break
					}

					if !db.Slots[index].Equal(res[col]) {
						t.Fatalf(
							"Query result is incorrect. %v != %v\n",
							db.Slots[index],
							res[col],
						)
					}
				}
			}
		}
	}
}

func BenchmarkBuildDB(b *testing.B) {
	setup()

	// benchmark index build time
	for i := 0; i < b.N; i++ {
		GenerateRandomDB(BenchmarkDBSize, SlotBytes)
	}
}

func BenchmarkQuerySecretShares(b *testing.B) {
	setup()

	db := GenerateRandomDB(BenchmarkDBSize, SlotBytes)
	queryA := db.NewIndexQueryShares(0, BenchmarkDBHeight, 2)[0]

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

	db := GenerateRandomDB(BenchmarkDBSize, SlotBytes)
	queryA := db.NewIndexQueryShares(0, 1, 2)[0]

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

	db := GenerateRandomDB(BenchmarkDBSize, SlotBytes)
	queryA := db.NewIndexQueryShares(0, 1, 2)[0]

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
	db := GenerateRandomDB(BenchmarkDBSize, SlotBytes)
	query := db.NewEncryptedQuery(pk, int(BenchmarkDBSize/BenchmarkDBHeight), BenchmarkDBHeight, 1, 0)

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
	db := GenerateRandomDB(BenchmarkDBSize, SlotBytes)
	query := db.NewEncryptedQuery(pk, int(BenchmarkDBSize/BenchmarkDBHeight), BenchmarkDBHeight, 1, 0)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := db.PrivateEncryptedQuery(query, 8)

		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkRecursiveEncryptedQueryAHESingleThread(b *testing.B) {
	setup()

	_, pk := paillier.KeyGen(1024)
	db := GenerateRandomDB(BenchmarkDBSize, SlotBytes)
	query := db.NewDoublyEncryptedQuery(pk, int(BenchmarkDBSize/BenchmarkDBHeight), BenchmarkDBHeight, 1, 0, 0)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := db.PrivateDoublyEncryptedQuery(query, 1)

		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkRecursiveEncryptedQueryAHE8Thread(b *testing.B) {
	setup()

	_, pk := paillier.KeyGen(1024)
	db := GenerateRandomDB(BenchmarkDBSize, SlotBytes)
	query := db.NewDoublyEncryptedQuery(pk, int(BenchmarkDBSize/BenchmarkDBHeight), BenchmarkDBSize, 1, 0, 0)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := db.PrivateDoublyEncryptedQuery(query, 8)

		if err != nil {
			panic(err)
		}
	}
}
