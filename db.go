package pir

import (
	"math"
	"sync"

	"github.com/sachaservan/paillier"
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
	Slot                  *DoublyEncryptedSlot
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

	// width of databse given query.height
	dimWidth := int(math.Ceil(float64(len(db.Slots) / query.DimHeight)))

	var wg sync.WaitGroup

	// num bits to represent the index
	numBits := uint(math.Log2(float64(dimWidth)) + 1)

	// otherwise assume keyword based (32 bit keys)
	if query.IsKeywordBased {
		numBits = uint(32)
	}

	// init server DPF
	pf := ServerInitialize(query.PrfKeys, numBits)

	bits := make([]bool, dimWidth)
	// expand the DPF into the bits array
	for i := 0; i < dimWidth; i++ {
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
			if i%nprocs == 0 || i+1 == dimWidth {
				wg.Wait()
			}
		}
	}

	// mapping of results; one for each process
	results := make([][]*Slot, nprocs)

	nRowsPerProc := int(float64(dimWidth) / float64(nprocs))

	for i := 0; i < nprocs; i++ {
		results[i] = make([]*Slot, dimWidth)

		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			start := i * nRowsPerProc
			end := i*nRowsPerProc + nRowsPerProc

			// handle the edge case
			if i+1 == nprocs {
				end = dimWidth
			}

			// initialize the slots
			for col := 0; col < dimWidth; col++ {
				results[i][col] = &Slot{
					Data: make([]byte, db.SlotBytes),
				}
			}

			for row := start; row < end; row++ {
				for col := 0; col < dimWidth; col++ {

					slotIndex := row*dimWidth + col
					// xor if bit is set and within bounds
					if bits[row] && slotIndex < len(db.Slots) {
						XorSlots(results[i][col], db.Slots[slotIndex])
					}
				}
			}

		}(i)
	}

	wg.Wait()

	result := make([]*Slot, len(results[0]))
	copy(result, results[0])

	for i := 1; i < nprocs; i++ {
		for j := 0; j < dimWidth; j++ {
			XorSlots(result[j], results[i][j])
		}
	}

	return &SecretSharedQueryResult{db.SlotBytes, result}, nil
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
	dimWidth, dimHeight := db.GetDimentionsForDatabase(len(query.EBits))

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
					intArr, numBytesPerInt, err := db.Slots[slotIndex].ToBigIntArray(numCiphertextsPerSlot)
					if err != nil {
						panic(err)
					}

					// set the number of bytes that each ciphertest represents
					if numBytesPerCiphertext == 0 {
						numBytesPerCiphertext = numBytesPerInt
					}

					for j, val := range intArr {
						sel := query.Pk.ConstMult(query.EBits[row], paillier.ToGmpInt(val))
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

	// width of databse given query.height
	dimWidth := int(math.Ceil(float64(len(db.Slots) / len(query.EBitsRow))))

	// execute the row PIR query to get the encrypted row containing the result
	rowQuery := &EncryptedQuery{
		Pk:    query.Pk,
		EBits: query.EBitsRow,
	}
	rowQueryRes, err := db.PrivateEncryptedQuery(rowQuery, nprocs)
	if err != nil {
		return nil, err
	}

	// number of ciphertexts needed to encrypt a slot
	numCiphertextsPerSlot := len(rowQueryRes.Slots[0].Cts)

	// need to encrypt each of the ciphertexts representing one slot
	res := make([]*paillier.Ciphertext, numCiphertextsPerSlot)

	// initialize the slots
	for col := 0; col < numCiphertextsPerSlot; col++ {
		res[col] = nullCiphertext(paillier.EncLevelTwo)
	}

	// apply the PIR column query to get the desired column ciphertext
	for col := 0; col < dimWidth; col++ {

		// "selection" bit
		bitCt := query.EBitsCol[col]

		slotCiphertexts := rowQueryRes.Slots[col].Cts
		for i, slotCiphertext := range slotCiphertexts {
			ctBytes := slotCiphertext.C.Bytes()
			ctSlot := &Slot{
				Data: ctBytes,
			}

			// each column ciphertext can encrypted one row ciphertext (see paillier)
			intArr, _, err := ctSlot.ToBigIntArray(1)
			if err != nil {
				panic(err)
			}

			for _, val := range intArr {
				sel := query.Pk.ConstMult(bitCt, paillier.ToGmpInt(val))
				res[i] = query.Pk.Add(res[i], sel)
			}
		}
	}

	resSlot := &DoublyEncryptedSlot{
		Cts: res,
	}

	queryResult := &DoublyEncryptedQueryResult{
		Pk:                    query.Pk,
		Slot:                  resSlot,
		NumBytesPerCiphertext: rowQueryRes.NumBytesPerCiphertext,
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
func (dbmd *DBMetadata) GetDimentionsForDatabase(height int) (int, int) {
	dimWidth := int(math.Ceil(float64(dbmd.DBSize / height)))
	dimHeight := height

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
