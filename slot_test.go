package pir

import (
	srand "crypto/rand"
	"math"
	"math/rand"
	"strconv"
	"strings"
	"testing"
)

func TestToFromString(t *testing.T) {

	if NewSlotFromString("test", len("test")).ToString() != "test" {
		t.Fail()
	}
}

func TestToFromBigIntArray(t *testing.T) {
	setup()

	for numBytes := 1; numBytes < 100; numBytes++ {

		slotData := make([]byte, numBytes)
		_, err := srand.Read(slotData)
		if err != nil {
			panic(err)
		}

		if _, _, err := NewSlot(slotData).ToBigIntArray(0); err == nil {
			t.Fatal("Did not throw error when 0 chunks specified")
		}

		// try up to numBytes * 2 to ensure we can chunk into more
		// chunks than there are bytes
		for i := 1; i < numBytes*2; i++ {
			slot := NewSlot(slotData)
			ints, numBytesPerInt, err := slot.ToBigIntArray(i)

			if err != nil {
				t.Fatal(err)
			}

			t.Logf("NumBytesPerChunck %v\n", numBytesPerInt)

			if len(ints) != i {
				t.Fatalf(
					"Incorrect number of chunks returned, expected %v, got %v\n",
					i,
					len(ints),
				)
			}

			recovered := NewSlotFromBigIntArray(ints, numBytes, numBytesPerInt)
			if !recovered.Equal(slot) {
				t.Fatalf(
					"Incorrect conversion when chunking into %v chunks, expected %v, got %v\n",
					i,
					slot,
					recovered,
				)
			}
		}
	}
}

func randomSlot(numBytes int) *Slot {
	slotData := make([]byte, numBytes)
	_, err := srand.Read(slotData)
	if err != nil {
		panic(err)
	}

	return &Slot{
		slotData,
	}
}

func randomString(numBytes int) string {

	max := int(math.Pow(2, float64(numBytes*8)))
	val := rand.Intn(max)
	return strconv.Itoa(val)
}

func TestCompareStrings(t *testing.T) {

	for numBytes := 1; numBytes < 8; numBytes++ {

		slotA := randomSlot(numBytes)
		slotB := randomSlot(numBytes)

		expected := slotA.Compare(slotB)
		actual := strings.Compare(slotA.ToString(), slotB.ToString())

		if expected != actual {
			t.Fatalf("Incorrect comparison order between bytes and strings %v vs %v\n",
				expected,
				actual,
			)
		}
	}

	for numBytes := 1; numBytes < 8; numBytes++ {

		stringA := randomString(numBytes)
		stringB := randomString(numBytes)

		expected := strings.Compare(stringA, stringB)
		actual := NewSlotFromString(stringA, numBytes).Compare(NewSlotFromString(stringB, numBytes))

		if expected != actual {
			t.Fatalf("Incorrect comparison order between bytes and strings %v vs %v\n",
				expected,
				actual,
			)
		}
	}
}

func TestEqual(t *testing.T) {

	bytesA := [...]byte{0, 0, 0, 0}
	bytesB := [...]byte{1, 0, 1, 0}
	bytesC := [...]byte{0, 0, 0, 0}
	bytesD := [...]byte{1, 0, 1, 0}

	slotA := NewSlot(bytesA[:])
	slotB := NewSlot(bytesB[:])
	slotC := NewSlot(bytesC[:])
	slotD := NewSlot(bytesD[:])

	if slotA.Equal(slotB) {
		t.Fail()
	}

	if !slotA.Equal(slotC) {
		t.Fail()
	}

	if !slotB.Equal(slotD) {
		t.Fail()
	}
}

func TestXorSlots(t *testing.T) {

	bytesA := [...]byte{0, 0, 0, 0}
	bytesB := [...]byte{1, 1, 1, 1}
	bytesXorAB := [...]byte{1, 1, 1, 1}

	bytesC := [...]byte{0, 0, 0, 0}
	bytesD := [...]byte{1, 0, 1, 0}
	bytesXorCD := [...]byte{1, 0, 1, 0}

	slotA := NewSlot(bytesA[:])
	slotB := NewSlot(bytesB[:])

	expectedXorAB := NewSlot(bytesXorAB[:])

	slotC := NewSlot(bytesC[:])
	slotD := NewSlot(bytesD[:])

	expectedXorCD := NewSlot(bytesXorCD[:])

	XorSlots(slotA, slotB)
	if !slotA.Equal(expectedXorAB) {
		t.Fail()
	}

	XorSlots(slotC, slotD)
	if !slotC.Equal(expectedXorCD) {
		t.Fail()
	}
}
