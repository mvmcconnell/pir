package pir

import (
	"errors"
	"math"
	"sync"

	"github.com/sachaservan/paillier"
	"github.com/sachaservan/pir/dpf"
)

// DBMetadata contains information on the layout
// and size information for a slot database type
type DBMetadata struct {
	SlotBytes int
	DBSize    int
}

// Database is a set of slots arranged in a grid of size width x height
// where each slot has size slotBytes
type Database struct {
	DBMetadata
	Slots    []*Slot
	Keywords []uint // set of keywords (optional)
}

// SecretSharedQueryResult contains shares of the resulting slots
type SecretSharedQueryResult struct {
	SlotBytes int
	Shares    []*Slot
}

// EncryptedSlot is an array of ciphertext bytes
type EncryptedSlot struct {
	Cts []*paillier.Ciphertext
}

// DoublyEncryptedSlot is an array of doubly encrypted ciphertexts
// which decrypt to a set of ciphertexts
// that then decrypt to a slot
type DoublyEncryptedSlot struct {
	Cts []*paillier.Ciphertext // note: level2 ciphertexts (see Paillier)
}

// EncryptedQueryResult is an array of encrypted slots
type EncryptedQueryResult struct {
	Slots                 []*EncryptedSlot
	Pk                    *paillier.PublicKey
	SlotBytes             int
	NumBytesPerCiphertext int
}

// DoublyEncryptedQueryResult is an array of encrypted slots
type DoublyEncryptedQueryResult struct {
	Slots                 []*DoublyEncryptedSlot
	Pk                    *paillier.PublicKey
	SlotBytes             int
	NumBytesPerCiphertext int
}

// NewDatabase returns an empty database
func NewDatabase() *Database {
	return &Database{}
}

// PrivateSecretSharedQuery uses the provided PIR query to retreive a slot row
func (db *Database) PrivateSecretSharedQuery(query *QueryShare, nprocs int) (*SecretSharedQueryResult, error) {

	// height of databse given query.GroupSize = dbWidth
	dimWidth := query.GroupSize
	dimHeight := int(math.Ceil(float64(db.DBSize / query.GroupSize)))

	var wg sync.WaitGroup

	// num bits to represent the index
	numBits := uint(math.Log2(float64(dimHeight)) + 1)

	// otherwise assume keyword based (32 bit keys)
	if query.IsKeywordBased {
		numBits = uint(32)
	}

	// init server DPF
	pf := dpf.ServerInitialize(query.PrfKeys, numBits)

	bits := make([]bool, dimHeight)
	// expand the DPF into the bits array
	for i := 0; i < dimHeight; i++ {
		// key (index or uint) depending on whether
		// the query is keyword based or index based
		// when keyword based use FSS
		key := uint(i)
		if query.IsKeywordBased {
			key = db.Keywords[i]
		}

		// don't spin up go routines in the single-thread case
		if nprocs == 1 {
			if query.IsTwoParty {
				res := pf.Evaluate2P(query.ShareNumber, query.KeyTwoParty, key)
				// IMPORTANT: take mod 2 of uint *before* casting to float64, otherwise there is an overflow edge case!
				bits[i] = (int(math.Abs(float64(res%2))) == 0)
			} else {
				res := pf.EvaluateMP(query.KeyMultiParty, key)
				// IMPORTANT: take mod 2 of uint *before* casting to float64, otherwise there is an overflow edge case!
				bits[i] = (int(math.Abs(float64(res%2))) == 0)
			}

		} else {
			wg.Add(1)
			go func(i int, key uint) {
				defer wg.Done()

				if query.IsTwoParty {
					res := pf.Evaluate2P(query.ShareNumber, query.KeyTwoParty, key)
					// IMPORTANT: take mod 2 of uint *before* casting to float64, otherwise there is an overflow edge case!
					bits[i] = (int(math.Abs(float64(res%2))) == 0)
				} else {
					res := pf.EvaluateMP(query.KeyMultiParty, key)
					// IMPORTANT: take mod 2 of uint *before* casting to float64, otherwise there is an overflow edge case!
					bits[i] = (int(math.Abs(float64(res%2))) == 0)
				}

			}(i, key)

			// launch nprocs threads in parallel to evaluate the DPF
			if i%nprocs == 0 || i+1 == dimHeight {
				wg.Wait()
			}
		}
	}

	// mapping of results; one for each process
	results := make([]*Slot, dimWidth)

	// initialize the slots
	for col := 0; col < dimWidth; col++ {
		results[col] = &Slot{
			Data: make([]byte, db.SlotBytes),
		}
	}

	for row := 0; row < dimHeight; row++ {

		if bits[row] {
			for col := 0; col < dimWidth; col++ {
				slotIndex := row*dimWidth + col
				// xor if bit is set and within bounds
				if slotIndex < len(db.Slots) {
					XorSlots(results[col], db.Slots[slotIndex])
				} else {
					break
				}
			}
		}
	}

	return &SecretSharedQueryResult{db.SlotBytes, results}, nil
}

func nullCiphertext(level paillier.EncryptionLevel) *paillier.Ciphertext {
	return &paillier.Ciphertext{C: paillier.OneBigInt, Level: level}
}

// PrivateEncryptedQuery uses the provided PIR query to retreive a slot row (encrypted)
// the tricky details are in regards to converting slot bytes to ciphertexts, specifically
// the encryption scheme might not have a message space large enough to accomodate
// all the bytes in a slot, thus requiring the bytes to be split up into several ciphertexts
func (db *Database) PrivateEncryptedQuery(query *EncryptedQuery, nprocs int) (*EncryptedQueryResult, error) {

	// width of databse given query.height
	dimWidth, dimHeight := query.DBWidth, query.DBHeight

	// how many ciphertexts are needed to represent a slot
	msgSpaceBytes := float64(len(query.Pk.N.Bytes()) - 2)
	numCiphertextsPerSlot := int(math.Ceil(float64(db.SlotBytes) / msgSpaceBytes))

	numBytesPerCiphertext := 0

	// mapping of results; one for each process
	slotRes := make([][]*EncryptedSlot, nprocs)

	// how many rows each process gets
	numRowsPerProc := int(float64(dimHeight) / float64(nprocs))

	var wg sync.WaitGroup

	for i := 0; i < nprocs; i++ {
		slotRes[i] = make([]*EncryptedSlot, dimWidth)

		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			start := i * numRowsPerProc
			end := i*numRowsPerProc + numRowsPerProc

			// handle the edge case
			if i+1 == nprocs {
				end = dimHeight
			}

			// initialize the slots
			for col := 0; col < dimWidth; col++ {
				slotRes[i][col] = &EncryptedSlot{
					Cts: make([]*paillier.Ciphertext, numCiphertextsPerSlot),
				}

				for j := range slotRes[i][col].Cts {
					slotRes[i][col].Cts[j] = nullCiphertext(paillier.EncLevelOne)
				}
			}

			for row := start; row < end; row++ {
				for col := 0; col < dimWidth; col++ {
					slotIndex := row*dimWidth + col
					if slotIndex >= len(db.Slots) {
						continue
					}

					// convert the slot into big.Int array
					intArr, numBytesPerInt, err := db.Slots[slotIndex].ToGmpIntArray(numCiphertextsPerSlot)
					if err != nil {
						panic(err)
					}

					// set the number of bytes that each ciphertest represents
					if numBytesPerCiphertext == 0 {
						numBytesPerCiphertext = numBytesPerInt
					}

					for j, val := range intArr {
						sel := query.Pk.ConstMult(query.EBits[row], val)
						slotRes[i][col].Cts[j] = query.Pk.Add(slotRes[i][col].Cts[j], sel)
					}
				}
			}

		}(i)
	}

	wg.Wait()

	slots := slotRes[0]
	for i := 1; i < nprocs; i++ {
		for j := 0; j < dimWidth; j++ {
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

	if query.Row.GroupSize > db.DBSize || query.Row.GroupSize == 0 {
		return nil, errors.New("invalid group size provided in query")
	}

	if query.Col.GroupSize > query.Row.DBWidth || query.Col.GroupSize == 0 {
		return nil, errors.New("invalid group size provided in query")
	}

	// get the row
	rowQueryRes, err := db.PrivateEncryptedQuery(query.Row, nprocs)
	if err != nil {
		return nil, err
	}

	return db.PrivateEncryptedQueryOverEncryptedResult(query.Col, rowQueryRes, nprocs)
}

// PrivateEncryptedQueryOverEncryptedResult executes the query over an encrypted query result
func (db *Database) PrivateEncryptedQueryOverEncryptedResult(query *EncryptedQuery, result *EncryptedQueryResult, nprocs int) (*DoublyEncryptedQueryResult, error) {

	// number of ciphertexts needed to encrypt a slot
	numCiphertextsPerSlot := len(result.Slots[0].Cts)

	if len(result.Slots)%query.GroupSize != 0 {
		panic("row has a size that is not a multiple of the group size")
	}

	// need to encrypt each of the ciphertexts representing one slot
	// res is a 2D array where each row is an encrypted slot composed of possibly multiple ciphertexts
	res := make([][]*paillier.Ciphertext, query.GroupSize)

	// initialize the slots
	for i := 0; i < query.GroupSize; i++ {
		res[i] = make([]*paillier.Ciphertext, numCiphertextsPerSlot)
		for j := 0; j < numCiphertextsPerSlot; j++ {
			res[i][j] = nullCiphertext(paillier.EncLevelTwo)
		}
	}

	// group memeber
	member := 0

	// apply the PIR column query to get the desired column ciphertext
	for col := 0; col < len(result.Slots); col++ {

		if col%query.GroupSize == 0 {
			member = 0
		}

		// "selection" bit
		bitIndex := int(col / query.GroupSize)
		bitCt := query.EBits[bitIndex]

		slotCiphertexts := result.Slots[col].Cts
		for j, slotCiphertext := range slotCiphertexts {
			ctVal := slotCiphertext.C

			sel := query.Pk.ConstMult(bitCt, ctVal)
			res[member][j] = query.Pk.Add(res[member][j], sel)
		}

		member++
	}

	resSlots := make([]*DoublyEncryptedSlot, query.GroupSize)

	for i, cts := range res {
		resSlots[i] = &DoublyEncryptedSlot{
			Cts: cts,
		}
	}

	queryResult := &DoublyEncryptedQueryResult{
		Pk:                    query.Pk,
		Slots:                 resSlots,
		NumBytesPerCiphertext: result.NumBytesPerCiphertext,
		SlotBytes:             db.SlotBytes,
	}

	return queryResult, nil

}

// BuildForData constrcuts a PIR database
// of slots where each string gets a slot
// and automatically finds the bandwidth-optimal
// width and height for PIR
func (db *Database) BuildForData(data []string) {

	slotSize := GetRequiredSlotSize(data)
	db.BuildForDataWithSlotSize(data, slotSize)
}

// BuildForDataWithSlotSize constrcuts a PIR database
// of slots where each string gets a slot of the specified size
func (db *Database) BuildForDataWithSlotSize(data []string, slotSize int) {

	db.Slots = make([]*Slot, len(data))
	db.SlotBytes = slotSize
	db.DBSize = len(data)

	for i := 0; i < len(data); i++ {
		slotData := make([]byte, slotSize)

		stringData := []byte(data[i])
		copy(slotData[:], stringData)

		// make a new slot with slotData
		db.Slots[i] = &Slot{
			Data: slotData,
		}
	}
}

// SetKeywords set the keywords (uints) associated with each row of the database
func (db *Database) SetKeywords(keywords []uint) {
	db.Keywords = keywords
}

// IndexToCoordinates returns the 2D coodindates for an index
// a PIR query should use the first value to recover the row
// and the second value to recover the column in the response
func (dbmd *DBMetadata) IndexToCoordinates(index, width, height int) (int, int) {
	return int(index / width), int(index % width)
}

// GetDimentionsForDatabase returns the width and height given a height constraint
// height is the desired height of the database (number of rows)
// groupSize is the number of *adjacent* slots needed to constitute a "group" (default = 1)
func (dbmd *DBMetadata) GetDimentionsForDatabase(height int, groupSize int) (int, int) {
	return dbmd.GetDimentionsForDatabaseWidthMultiple(height, groupSize, 1)
}

// GetDimentionsForDatabaseWidthMultiple returns width and height for the database such that
// widthMultiple is a multiple of the width value
func (dbmd *DBMetadata) GetDimentionsForDatabaseWidthMultiple(height int, groupSize int, widthMultiple int) (int, int) {
	dimWidth := int(math.Ceil(float64(dbmd.DBSize / height)))

	// make the dimWidth a multiple of groupSize
	if dimWidth%groupSize != 0 {
		dimWidth += groupSize - dimWidth%groupSize // next multiple
	}

	dimHeight := height

	// make sure the width is a multiple of widthMultiple
	if widthMultiple > 0 && dimWidth%widthMultiple != 0 {
		dimWidth += widthMultiple - dimWidth%widthMultiple // next multiple
	}

	// trim the height to fit the database without extra rows
	dimHeight = int(math.Ceil(float64(dbmd.DBSize / dimWidth)))

	return dimWidth, dimHeight
}

// GetSqrtOfDBSize returns sqrt(DBSize) + 1
func (dbmd *DBMetadata) GetSqrtOfDBSize() int {
	return int(math.Sqrt(float64(dbmd.DBSize)) + 1)
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

func addEncryptedSlots(pk *paillier.PublicKey, a, b *EncryptedSlot) {

	for j := 0; j < len(b.Cts); j++ {
		a.Cts[j] = pk.Add(a.Cts[j], b.Cts[j])
	}
}
