package pir

import (
	"fmt"
	"math/rand"
)

// GenerateRandomDB generates a database of slots (where each slot is of size NumBytes)
// the width and height parameter specify the number of rows and columns in the database
func GenerateRandomDB(width, height, numBytes int) *Database {
	db := Database{}
	db.Slots = make([][]*Slot, height)
	db.Width = width
	db.Height = height
	db.SlotBytes = numBytes

	for row := 0; row < height; row++ {
		db.Slots[row] = make([]*Slot, width)
		for col := 0; col < width; col++ {
			slotData := make([]byte, numBytes)
			_, err := rand.Read(slotData)
			if err != nil {
				panic(fmt.Sprintf("Generating random bytes failed with %v\n", err))
			}

			// make a new slot with slotData
			db.Slots[row][col] = &Slot{
				Data: slotData,
			}
		}
	}

	return &db
}
