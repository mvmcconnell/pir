package pir

import (
	"bytes"
	"errors"
	"math"

	"github.com/ncw/gmp"
)

// Slot is a set of bytes which can be xor'ed and comapred
type Slot struct {
	Data []byte
}

// XorSlots compute xor a and b storing result in a
func XorSlots(a, b *Slot) {

	for j := 0; j < len(b.Data); j++ {
		a.Data[j] ^= b.Data[j]
	}
}

// Equal compute xor a and b storing result in a
func (slot *Slot) Equal(other *Slot) bool {

	if slot == nil || other == nil {
		return false
	}

	if len(slot.Data) != len(other.Data) {
		return false
	}

	for j := 0; j < len(other.Data); j++ {
		if slot.Data[j] != other.Data[j] {
			return false
		}
	}

	return true
}

// Compare returns the comparison of the two byte arrays
// 0 if slot == other
// -1 if slot < other
// 1 if slot > other
func (slot *Slot) Compare(other *Slot) int {
	return bytes.Compare(slot.Data, other.Data)
}

// ToString converts slot data to a string
func (slot *Slot) ToString() string {
	return string(removeTrailingZeros(slot.Data))
}

// ToGmpIntArray converts the slot into an array of
// big.Ints where
func (slot *Slot) ToGmpIntArray(numChuncks int) ([]*gmp.Int, int, error) {

	if numChuncks <= 0 {
		return nil, -1, errors.New("cannot divide data indo 0 chuncks")
	}

	numBytesPerChunck := int(math.Max(1, math.Ceil(float64(len(slot.Data))/float64(numChuncks))))

	res := make([]*gmp.Int, numChuncks)
	for i := 0; i < numChuncks; i++ {

		start := i * numBytesPerChunck
		end := int(math.Min(float64(len(slot.Data)), float64(start+numBytesPerChunck)))

		res[i] = new(gmp.Int)

		// don't fill in the bytes if more chunks
		// specified than there is data
		if start >= end {
			continue
		}

		res[i].SetBytes(slot.Data[start:end])
	}

	return res, numBytesPerChunck, nil
}

// NewSlotFromGmpIntArray parses an array of ints into a slot type
// numBytes is the final size of the slot
// numBytesPerInt the the number of bytes to extract from each int
func NewSlotFromGmpIntArray(arr []*gmp.Int, numBytes int, numBytesPerInt int) *Slot {

	// each encrypted slot has an array of ciphertexts
	// encoding the slot data
	bytes := make([]byte, numBytes)
	nextByte := 0
	for _, v := range arr {

		//  only shift if we're not on the last (real) byte
		shiftZeros := nextByte+numBytesPerInt <= numBytes

		// bytes() returns only significant bytes
		// therefore, we increment nextByte to ensure leading (rather than trailing)
		// zeros in the resulting slot bytes
		if shiftZeros && len(v.Bytes()) <= numBytesPerInt {
			nextByte += numBytesPerInt - len(v.Bytes())
		}

		// if this is the last byte, it may be the case that
		// there are fewer than numBytesPerInt to extract but
		// it may also be the case that those bytes
		// have a leading zero, thus it is necessary to undo the shift
		// above and then adjust based on the remaining bytes
		// to ensure leading zeros are incorporated
		if !shiftZeros {
			nextByte += (numBytes - nextByte - len(v.Bytes()))
		}

		// assign each byte to to the slot data array
		for _, b := range v.Bytes() {
			bytes[nextByte] = b
			nextByte++
		}
	}

	return NewSlot(bytes)
}

// NewSlotFromString converts a string to a slot type
func NewSlotFromString(s string, slotSize int) *Slot {
	b := []byte(s)
	for i := 0; i < (slotSize - len(s)); i++ {
		b = append(b, 0)
	}
	return &Slot{
		Data: b,
	}
}

// NewSlot returns a slot populated with data
func NewSlot(b []byte) *Slot {
	return &Slot{
		Data: b,
	}
}

// GetRequiredSlotSize returns the minimum number of
// bytes required to represent each data point
func GetRequiredSlotSize(data []string) int {

	minBytes := 0
	for _, s := range data {
		// len() returns the number of bytes required
		// to represent the string
		if len(s) > minBytes {
			minBytes = len(s)
		}
	}

	return minBytes
}

func removeTrailingZeros(data []byte) []byte {

	res := make([]byte, 0)
	firstNonZeroFound := false
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] != 0 {
			firstNonZeroFound = true
		}

		if firstNonZeroFound {
			res = append(res, data[i])
		}
	}

	if len(res) == 0 {
		res = append(res, 0)
	}

	return reverse(res)
}

func reverse(numbers []byte) []byte {
	for i, j := 0, len(numbers)-1; i < j; i, j = i+1, j-1 {
		numbers[i], numbers[j] = numbers[j], numbers[i]
	}
	return numbers
}
