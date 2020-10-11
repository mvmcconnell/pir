package pir

import (
	"errors"
	"math"
	"sync"

	he "github.com/sachaservan/hewrap"
)

// DBMetadata contains information on the layout
// and size information for a slot database type
type DBMetadata struct {
	SlotBytes     int
	Width, Height int
}

// Database is a set of slots arranged in a grid of size width x height
// where each slot has size slotBytes
type Database struct {
	DBMetadata
	Slots    [][]*Slot
	Keywords []uint // set of keywords (optional)
}

// SecretSharedQueryResult contains shares of the resulting slots
type SecretSharedQueryResult struct {
	SlotBytes int
	Shares    []*Slot
}

// EncryptedSlot is an array of ciphertext bytes
type EncryptedSlot struct {
	Cts []*he.Ciphertext
}

// DoublyEncryptedSlot is an array of doubly encrypted ciphertexts
// which decrypt to a set of ciphertexts
// that then decrypt to a slot
type DoublyEncryptedSlot struct {
	Cts [][]*he.Ciphertext
}

// EncryptedQueryResult is an array of encrypted slots
type EncryptedQueryResult struct {
	Slots                 []*EncryptedSlot
	Pk                    *he.PublicKey
	SlotBytes             int
	NumBytesPerCiphertext int
}

// DoublyEncryptedQueryResult is an array of encrypted slots
type DoublyEncryptedQueryResult struct {
	Slot                           *DoublyEncryptedSlot
	Pk                             *he.PublicKey
	SlotBytes                      int
	NumBytesPerCiphertext          int
	NumBytesPerEncryptedCiphertext int

	// number of ciphertexts needed to encrypt
	// one ciphertext in the same scheme
	NumCiphertextsPerPartialCiphertext int
}

// NewDatabase returns an empty database
func NewDatabase() *Database {
	return &Database{}
}

// PrivateSecretSharedQuery uses the provided PIR query to retreive a slot row
func (db *Database) PrivateSecretSharedQuery(query *QueryShare, nprocs int) (*SecretSharedQueryResult, error) {

	var wg sync.WaitGroup

	// num bits to represent the index
	numBits := uint(math.Log2(float64(db.Height)) + 1)

	// otherwise assume keyword based (32 bit keys)
	if query.IsKeywordBased {
		numBits = uint(32)
	}

	// init server DPF
	pf := ServerInitialize(query.PrfKeys, numBits)

	bits := make([]bool, db.Height)
	// expand the DPF into the bits array
	for i := 0; i < db.Height; i++ {
		// key (index or uint) depending on whether
		// the query is keyword based or index based
		// when keyword based use FSS
		key := uint(i)
		if query.IsKeywordBased {
			key = db.Keywords[i]
		}

		wg.Add(1)
		go func(i int, key uint) {
			defer wg.Done()

			if query.IsTwoParty {
				res := pf.Evaluate2P(query.ShareNumber, query.KeyTwoParty, key)
				bits[i] = (int(math.Abs(float64(res)))%2 == 1)
			} else {
				res := pf.EvaluateMP(query.KeyMultiParty, key)
				bits[i] = (int(math.Abs(float64(res)))%2 == 1)
			}

		}(i, key)
	}

	wg.Wait()

	// mapping of results; one for each process
	results := make([][]*Slot, nprocs)

	nRowsPerProc := int(float64(db.Height) / float64(nprocs))

	for i := 0; i < nprocs; i++ {
		results[i] = make([]*Slot, db.Width)

		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			start := i * nRowsPerProc
			end := i*nRowsPerProc + nRowsPerProc

			// handle the edge case
			if i+1 == nprocs {
				end = db.Height
			}

			// initialize the slots
			for col := 0; col < db.Width; col++ {
				results[i][col] = &Slot{
					Data: make([]byte, db.SlotBytes),
				}
			}

			for row := start; row < end; row++ {
				for col := 0; col < db.Width; col++ {
					if bits[row] {
						XorSlots(results[i][col], db.Slots[row][col])
					}
				}
			}

		}(i)
	}

	wg.Wait()

	result := make([]*Slot, len(results[0]))
	copy(result, results[0])

	for i := 1; i < nprocs; i++ {
		for j := 0; j < db.Width; j++ {
			XorSlots(result[j], results[i][j])
		}
	}

	return &SecretSharedQueryResult{db.SlotBytes, result}, nil
}

// PrivateEncryptedQuery uses the provided PIR query to retreive a slot row (encrypted)
// the tricky details are in regards to converting slot bytes to ciphertexts, specifically
// the encryption scheme might not have a message space large enough to accomodate
// all the bytes in a slot, thus requiring the bytes to be split up into several ciphertexts
func (db *Database) PrivateEncryptedQuery(query *EncryptedQuery, nprocs int) (*EncryptedQueryResult, error) {

	if len(query.EBits) != db.Height {
		return nil, errors.New("query is not formatted correctly (height != number of row bits)")
	}

	// how many ciphertexts are needed to represent a slot
	msgSpaceBytes := float64(len(query.Pk.MessageSpace().Bytes()) - 2)
	numCiphertextsPerSlot := int(math.Ceil(float64(db.SlotBytes) / msgSpaceBytes))

	numBytesPerCiphertext := 0

	// mapping of results; one for each process
	slotRes := make([][]*EncryptedSlot, nprocs)

	// how many rows each process gets
	numRowsPerProc := int(float64(db.Height) / float64(nprocs))

	var wg sync.WaitGroup

	for i := 0; i < nprocs; i++ {
		slotRes[i] = make([]*EncryptedSlot, db.Width)

		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			start := i * numRowsPerProc
			end := i*numRowsPerProc + numRowsPerProc

			// handle the edge case
			if i+1 == nprocs {
				end = db.Height
			}

			// initialize the slots
			for col := 0; col < db.Width; col++ {
				slotRes[i][col] = &EncryptedSlot{
					Cts: make([]*he.Ciphertext, numCiphertextsPerSlot),
				}

				for j := range slotRes[i][col].Cts {
					slotRes[i][col].Cts[j] = query.Pk.NullCiphertext()
				}
			}

			for row := start; row < end; row++ {
				for col := 0; col < db.Width; col++ {
					// convert the slot into big.Int array
					intArr, numBytesPerInt, err := db.Slots[row][col].ToBigIntArray(numCiphertextsPerSlot)
					if err != nil {
						panic(err)
					}

					// set the number of bytes that each ciphertest represents
					if numBytesPerCiphertext == 0 {
						numBytesPerCiphertext = numBytesPerInt
					}

					for j, val := range intArr {
						sel := query.Pk.ConstMul(query.EBits[row], val)
						slotRes[i][col].Cts[j] = query.Pk.Add(slotRes[i][col].Cts[j], sel)
					}
				}
			}

		}(i)
	}

	wg.Wait()

	slots := slotRes[0]
	for i := 1; i < nprocs; i++ {
		for j := 0; j < db.Width; j++ {
			addEncryptedSlots(query.Pk, slots[j], slotRes[i][j])
		}
	}

	queryResult := &EncryptedQueryResult{
		Pk:                    query.Pk,
		Slots:                 slots,
		NumBytesPerCiphertext: numBytesPerCiphertext,
		SlotBytes:             db.SlotBytes,
	}

	return queryResult, nil
}

// PrivateDoublyEncryptedQuery executes a row PIR query and col PIR query by recursively
// applying PrivateEncryptedQuery
func (db *Database) PrivateDoublyEncryptedQuery(query *DoublyEncryptedQuery, nprocs int) (*DoublyEncryptedQueryResult, error) {

	if len(query.EBitsCol) != db.Width {
		return nil, errors.New("query is not formatted correctly (width != number of column bits)")
	}

	// execute the row PIR query to get the encrypted row containing the result
	rowQuery := &EncryptedQuery{
		Pk:    query.Pk,
		EBits: query.EBitsRow,
	}
	rowQueryRes, err := db.PrivateEncryptedQuery(rowQuery, nprocs)
	if err != nil {
		return nil, err
	}

	// number of bytes needed to represent a ciphertext
	maxEncodedCiphertextBytes := 0
	for _, s := range rowQueryRes.Slots {
		for _, c := range s.Cts {
			b, _ := c.Bytes()
			l := len(b)
			if maxEncodedCiphertextBytes < l {
				maxEncodedCiphertextBytes = l
			}
		}
	}

	msgSpaceBytes := len(query.Pk.MessageSpace().Bytes()) - 2

	// number of ciphertexts needed to encrypt a slot
	numCiphertextsPerSlot := len(rowQueryRes.Slots[0].Cts)

	// number of ciphertexts needed to PIR over the encrypted row slots
	numCiphertextsPerPartialCiphertext := int(math.Ceil(float64(maxEncodedCiphertextBytes) / float64(msgSpaceBytes)))
	numBytesPerEncryptedCiphertext := 0

	// need to encrypt each of the ciphertexts representing one slot
	res := make([][]*he.Ciphertext, numCiphertextsPerSlot)

	// initialize the slots
	for col := 0; col < numCiphertextsPerSlot; col++ {
		res[col] = make([]*he.Ciphertext, numCiphertextsPerPartialCiphertext)
		for j := range res[col] {
			res[col][j] = query.Pk.NullCiphertext()
		}
	}

	// apply the PIR column query to get the desired column ciphertext
	for col := 0; col < db.Width; col++ {

		// "selection" bit
		bitCt := query.EBitsCol[col]

		slotCiphertexts := rowQueryRes.Slots[col].Cts
		for i, slotCiphertext := range slotCiphertexts {
			ctBytes, _ := slotCiphertext.Bytes()
			ctSlot := &Slot{
				Data: ctBytes,
			}

			intArr, numBytesPerInt, err := ctSlot.ToBigIntArray(numCiphertextsPerPartialCiphertext)
			if err != nil {
				panic(err)
			}

			if numBytesPerEncryptedCiphertext == 0 {
				numBytesPerEncryptedCiphertext = numBytesPerInt
			}

			for j, val := range intArr {
				sel := query.Pk.ConstMul(bitCt, val)
				res[i][j] = query.Pk.Add(res[i][j], sel)
			}
		}
	}

	resSlot := &DoublyEncryptedSlot{
		Cts: res,
	}

	queryResult := &DoublyEncryptedQueryResult{
		Pk:                                 query.Pk,
		Slot:                               resSlot,
		NumBytesPerCiphertext:              rowQueryRes.NumBytesPerCiphertext,
		NumCiphertextsPerPartialCiphertext: numCiphertextsPerPartialCiphertext,
		NumBytesPerEncryptedCiphertext:     numBytesPerEncryptedCiphertext,
		SlotBytes:                          db.SlotBytes,
	}

	return queryResult, nil

}

// BuildForData constrcuts a PIR database
// of slots where each string gets a slot
// and automatically finds the bandwidth-optimal
// width and height for PIR
func (db *Database) BuildForData(data []string) int {

	slotSize := GetRequiredSlotSize(data)
	return db.BuildForDataWithSlotSize(data, slotSize)
}

// BuildForDataWithSlotSize constrcuts a PIR database
// of slots where each string gets a slot of the specified size
func (db *Database) BuildForDataWithSlotSize(data []string, slotSize int) int {

	dbSize := len(data)

	width, height := GetOptimalDBDimentions(slotSize, dbSize)

	db.Slots = make([][]*Slot, height)
	db.Width = width
	db.Height = height
	db.SlotBytes = slotSize

	for row := 0; row < height; row++ {
		db.Slots[row] = make([]*Slot, width)
		for col := 0; col < width; col++ {
			slotData := make([]byte, slotSize)

			// when computing optimal dimentions,
			// there might be some extra slots created
			// so need to make sure its not out of bounds
			if len(data) > row*width+col {
				stringData := []byte(data[row*width+col])
				copy(slotData[:], stringData)
			}

			// make a new slot with slotData
			db.Slots[row][col] = &Slot{
				Data: slotData,
			}
		}
	}

	return slotSize
}

// BuildForDataWithDimentions constrcuts a PIR database with specified width and height
func (db *Database) BuildForDataWithDimentions(data []string, width, height int) int {

	slotSize := GetRequiredSlotSize(data)

	db.Slots = make([][]*Slot, height)
	db.Width = width
	db.Height = height
	db.SlotBytes = slotSize

	for row := 0; row < height; row++ {
		db.Slots[row] = make([]*Slot, width)
		for col := 0; col < width; col++ {
			slotData := make([]byte, slotSize)

			// when computing optimal dimentions,
			// there might be some extra slots created
			// so need to make sure its not out of bounds
			if len(data) > row*width+col {
				stringData := []byte(data[row*width+col])
				copy(slotData[:], stringData)
			}

			// make a new slot with slotData
			db.Slots[row][col] = &Slot{
				Data: slotData,
			}
		}
	}

	return slotSize
}

// SetKeywords set the keywords (uints) associated with each row of the database
func (db *Database) SetKeywords(keywords []uint) {
	db.Keywords = keywords
}

// IndexToCoordinates returns the 2D coodindates for an index
// a PIR query should use the first value to recover the row
// and the second value to recover the column in the response
func (dbmd *DBMetadata) IndexToCoordinates(index int) (int, int) {
	return int(index / dbmd.Width), int(index % dbmd.Width)
}

// GetOptimalDBDimentions returns the optimal DB dimentions for PIR
func GetOptimalDBDimentions(slotSize int, dbSize int) (int, int) {

	height := int(math.Max(1, math.Sqrt(float64(dbSize*slotSize))))
	width := math.Ceil(float64(dbSize) / float64(height))

	return int(width), int(height)
}

// GetOptimalWeightedDBDimentions returns the optimal DB dimentions for PIR
// where the height of the database is weighted by weight (int) >= 1
func GetOptimalWeightedDBDimentions(slotSize int, dbSize int, weight int) (int, int) {

	width, height := GetOptimalDBDimentions(slotSize, dbSize)

	newWidth := int(width / weight)
	newHeight := int(math.Ceil(float64(height * weight)))

	return newWidth, newHeight
}

func addEncryptedSlots(pk *he.PublicKey, a, b *EncryptedSlot) {

	for j := 0; j < len(b.Cts); j++ {
		a.Cts[j] = pk.Add(a.Cts[j], b.Cts[j])
	}
}
