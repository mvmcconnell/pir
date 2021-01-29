package dpf

import (
	"math"
	"math/rand"
	"testing"
)

const numTrials = 1000

func TestCorrectTwoServer(t *testing.T) {

	for trial := 0; trial < numTrials; trial++ {
		num := rand.Intn(1<<10) + 100

		specialIndex := uint(rand.Intn(num))
		outputValueAtSpecialIndex := uint(rand.Intn(num))

		// generate fss Keys on client
		fClient := ClientInitialize(uint(math.Log2(float64(num))) + 1)
		fssKeys := fClient.GenerateTwoServer(specialIndex, outputValueAtSpecialIndex)

		// simulate the server
		fServer := ServerInitialize(fClient.PrfKeys, fClient.NumBits)

		for i := 0; i < num; i++ {
			ans0 := fServer.Evaluate2P(0, fssKeys[0], uint(i))
			ans1 := fServer.Evaluate2P(1, fssKeys[1], uint(i))

			if uint(i) == specialIndex && uint(ans0+ans1) != outputValueAtSpecialIndex {
				t.Fatalf("Expected: %v Got: %v", outputValueAtSpecialIndex, ans0+ans1)
			}

			if uint(i) != specialIndex && ans0+ans1 != 0 {
				t.Fatalf("Expected: 0 Got: %v", ans0+ans1)
			}
		}
	}
}

func TestCorrectPointFunctionTwoServer(t *testing.T) {

	for trial := 0; trial < numTrials; trial++ {
		num := rand.Intn(1<<10) + 100

		specialIndex := uint(rand.Intn(num))

		// generate fss Keys on client
		fClient := ClientInitialize(uint(math.Log2(float64(num))) + 1)
		fssKeys := fClient.GenerateTwoServer(specialIndex, 1)

		// simulate the server
		fServer := ServerInitialize(fClient.PrfKeys, fClient.NumBits)

		for i := 0; i < num; i++ {
			ans0 := fServer.Evaluate2P(0, fssKeys[0], uint(i))
			ans1 := fServer.Evaluate2P(1, fssKeys[1], uint(i))

			ans0Bit := uint(math.Abs(float64(ans0 % 2)))
			ans1Bit := uint(math.Abs(float64(ans1 % 2)))

			if uint(i) == specialIndex && uint(ans0Bit^ans1Bit) != 1 {
				t.Fatalf("Expected: %v Got: %v", 1, ans0Bit^ans1Bit)
			}

			if uint(i) != specialIndex && ans0Bit^ans1Bit != 0 {
				t.Fatalf("Expected: 0 Got: %v", ans0^ans1)
			}
		}
	}
}

func TestCorrectTwoServerKeyword(t *testing.T) {

	for trial := 0; trial < numTrials; trial++ {
		num := rand.Intn(1 << 62)
		keyword := uint(rand.Intn(num))

		outputValueAtKeyword := uint(rand.Intn(1 << 32))

		// generate fss Keys on client
		fClient := ClientInitialize(64)
		fssKeys := fClient.GenerateTwoServer(keyword, outputValueAtKeyword)

		// simulate the server
		fServer := ServerInitialize(fClient.PrfKeys, fClient.NumBits)

		for i := 0; i < 100; i++ {

			testKeyword := uint(rand.Intn(num))
			if i == 0 {
				testKeyword = keyword
			}

			ans0 := fServer.Evaluate2P(0, fssKeys[0], testKeyword)
			ans1 := fServer.Evaluate2P(1, fssKeys[1], testKeyword)

			if testKeyword == keyword && uint(ans0+ans1) != outputValueAtKeyword {
				t.Fatalf("Expected: %v Got: %v", outputValueAtKeyword, ans0+ans1)
			}

			if testKeyword != keyword && ans0+ans1 != 0 {
				t.Fatalf("Expected: 0 Got: %v", ans0+ans1)
			}
		}
	}
}

func Benchmark2PartyServerInit(b *testing.B) {

	fClient := ClientInitialize(32)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ServerInitialize(fClient.PrfKeys, fClient.NumBits)
	}
}

func Benchmark2Party32BitKeywordEval(b *testing.B) {

	fClient := ClientInitialize(32)
	fssKeys := fClient.GenerateTwoServer(1, 1)
	fServer := ServerInitialize(fClient.PrfKeys, fClient.NumBits)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		fServer.Evaluate2P(0, fssKeys[0], uint(i))
	}
}

func Benchmark2Party64BitKeywordEval(b *testing.B) {

	fClient := ClientInitialize(64)
	fssKeys := fClient.GenerateTwoServer(1, 1)
	fServer := ServerInitialize(fClient.PrfKeys, fClient.NumBits)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		fServer.Evaluate2P(0, fssKeys[0], uint(i))
	}
}
