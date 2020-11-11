package pir

import (
	"fmt"
	"math/rand"
)

// GenerateRandomDB generates a database of slots (where each slot is of size NumBytes)
// the width and height parameter specify the number of rows and columns in the database
func GenerateRandomDB(size, numBytes int) *Database {

	db := Database{}
	db.Slots = make([]*Slot, size)
	db.SlotBytes = numBytes
	db.DBSize = size

	for i := 0; i < size; i++ {
		slotData := make([]byte, numBytes)
		_, err := rand.Read(slotData)
		if err != nil {
			panic(fmt.Sprintf("Generating random bytes failed with %v\n", err))
		}

		// make a new slot with slotData
		db.Slots[i] = &Slot{
			Data: slotData,
		}
	}

	return &db
}
