package dpf

import (
	"testing"
)

func TestCorrectTwoServer(t *testing.T) {

	// Generate fss Keys on client
	fClient := ClientInitialize(32)

	// Test with if x = 10, evaluate to 2
	fssKeys := fClient.GenerateTwoServer(10, 1)

	// Simulate server
	fServer := ServerInitialize(fClient.PrfKeys, fClient.NumBits)

	// Test 2-party Equality Function
	var ans0, ans1 int = 0, 0
	ans0 = fServer.Evaluate2P(0, fssKeys[0], 10)
	t.Logf("Answer 0: %v\n", ans0)

	ans1 = fServer.Evaluate2P(1, fssKeys[1], 10)
	t.Logf("Answer 1: %v\n", ans1)

	if ans0+ans1 == 0 {
		t.Fatalf("Expected: 1 Got: %v", ans0+ans1)
	}

	t.Logf("Match (should be 1): %v\n", ans0+ans1)

	ans0 = fServer.Evaluate2P(0, fssKeys[0], 11)
	ans1 = fServer.Evaluate2P(1, fssKeys[1], 11)
	t.Logf("No Match (should be 0): %v\n", ans0+ans1)

	if ans0+ans1 != 0 {
		t.Fatalf("Expected: 0 Got: %v", ans0+ans1)
	}

	ans0 = fServer.Evaluate2P(0, fssKeys[0], 9)
	ans1 = fServer.Evaluate2P(1, fssKeys[1], 9)
	t.Logf("No Match (should be 0): %v\n", ans0+ans1)

	if ans0+ans1 != 0 {
		t.Fatalf("Expected: 0 Got: %v", ans0+ans1)
	}
}

func TestCorrectMultiServer(t *testing.T) {

	// Generate fss Keys on client
	fClient := ClientInitialize(6)

	// Test with if x = 10, evaluate to 2
	fssKeys := fClient.GenerateMultiServer(10, 1, 3)

	// Simulate server
	fServer := ServerInitialize(fClient.PrfKeys, fClient.NumBits)

	// Test multi-party Equality Function
	ans0 := fServer.EvaluateMP(fssKeys[0], 9)
	ans1 := fServer.EvaluateMP(fssKeys[1], 9)
	ans2 := fServer.EvaluateMP(fssKeys[2], 9)

	if ans0^ans1^ans2 != 0 {
		t.Fatalf("Expected: 0 Got: %v", ans0^ans1^ans2)
	}
	t.Logf("No Match (should be zero): %v\n", ans0^ans1^ans2)

	ans0 = fServer.EvaluateMP(fssKeys[0], 10)
	ans1 = fServer.EvaluateMP(fssKeys[1], 10)
	ans2 = fServer.EvaluateMP(fssKeys[2], 10)

	if ans0+ans1+ans2 == 0 {
		t.Fatalf("Expected: 1 Got: %v", ans0^ans1^ans2)
	}
	t.Logf("Match (should be 1): %v\n", ans0^ans1^ans2)

	ans0 = fServer.EvaluateMP(fssKeys[0], 11)
	ans1 = fServer.EvaluateMP(fssKeys[1], 11)
	ans2 = fServer.EvaluateMP(fssKeys[2], 11)
	t.Logf("No Match (should be 0): %v\n", ans0^ans1^ans2)

	if ans0^ans1^ans2 != 0 {
		t.Fatalf("Expected: 0 Got: %v", ans0^ans1^ans2)
	}

}
