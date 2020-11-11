package pir

import (
	"math"
	"math/big"
	"math/rand"

	"github.com/sachaservan/paillier"
)

// QueryShare is a secret share of a query over the database
// to retrieve a row
type QueryShare struct {
	KeyTwoParty    *Key2P
	KeyMultiParty  *KeyMP
	PrfKeys        []*PrfKey
	IsKeywordBased bool
	IsTwoParty     bool
	ShareNumber    uint
	DimHeight      int // height of the database
}

// EncryptedQuery is an encryption of a point function
// that evaluates to 1 at the desired row in the database
// bits = (0, 0,.., 1, ...0, 0)
type EncryptedQuery struct {
	Pk    *paillier.PublicKey
	EBits []*paillier.Ciphertext
}

// DoublyEncryptedQuery consists of two encrypted point functions
// that evaluates to 1 at the desired row and column in the database
type DoublyEncryptedQuery struct {
	Pk        *paillier.PublicKey
	EBitsRow  []*paillier.Ciphertext
	EBitsCol  []*paillier.Ciphertext
	GroupSize int // how many elements to return
}

// NewIndexQueryShares generates PIR query shares for the index
func (dbmd *DBMetadata) NewIndexQueryShares(index uint, height int, numShares uint) []*QueryShare {
	return dbmd.newQueryShares(index, numShares, height, true)
}

// NewKeywordQueryShares generates keyword-based PIR query shares for keyword
func (dbmd *DBMetadata) NewKeywordQueryShares(keyword uint, height int, numShares uint) []*QueryShare {
	return dbmd.newQueryShares(keyword, numShares, height, false)
}

// NewQueryShares generates random PIR query shares for the index
func (dbmd *DBMetadata) newQueryShares(key uint, numShares uint, dimHeight int, isIndexQuery bool) []*QueryShare {

	// num bits to represent the index
	numBits := uint(math.Log2(float64(dimHeight)) + 1)

	// otherwise assume keyword based (32 bit keys)
	if !isIndexQuery {
		numBits = uint(32)
	}

	pf := ClientInitialize(numBits)

	var dpfKeysTwoParty []*Key2P
	var dpfKeysMultiParty []*KeyMP

	if numShares == 2 {
		dpfKeysTwoParty = pf.GenerateTwoServer(key, 1)
	} else {
		dpfKeysMultiParty = pf.GenerateMultiServer(key, 1, numShares)
	}

	if key >= uint(dimHeight) {
		panic("requesting key outside of domain")
	}

	shares := make([]*QueryShare, numShares)
	for i := 0; i < int(numShares); i++ {
		shares[i] = &QueryShare{}
		shares[i].ShareNumber = uint(i)
		shares[i].PrfKeys = pf.PrfKeys
		shares[i].IsKeywordBased = !isIndexQuery
		shares[i].DimHeight = dimHeight

		if numShares == 2 {
			shares[i].KeyTwoParty = dpfKeysTwoParty[i]
			shares[i].IsTwoParty = true
		} else {
			shares[i].KeyMultiParty = dpfKeysMultiParty[i]
			shares[i].IsTwoParty = false
		}
	}

	return shares
}

// NewEncryptedQuery generates a new encrypted point function that acts as a PIR query
func (dbmd *DBMetadata) NewEncryptedQuery(pk *paillier.PublicKey, height int, index int) *EncryptedQuery {

	res := make([]*paillier.Ciphertext, height)
	for i := 0; i < height; i++ {
		if i == index {
			res[i] = pk.EncryptOne()
		} else {
			res[i] = pk.EncryptZero()
		}
	}

	return &EncryptedQuery{
		Pk:    pk,
		EBits: res,
	}
}

// NewDoublyEncryptedQuery generates two encrypted point function that acts as a PIR query
// to select the row and column in the database
func (dbmd *DBMetadata) NewDoublyEncryptedQuery(pk *paillier.PublicKey, height int, rowIndex, colIndex int) *DoublyEncryptedQuery {

	// width of databse given query.height
	dimWidth, dimHeight := dbmd.GetDimentionsForDatabase(height)

	row := make([]*paillier.Ciphertext, dimHeight)
	col := make([]*paillier.Ciphertext, dimWidth)
	for i := 0; i < dimHeight; i++ {
		if i == rowIndex {
			row[i] = pk.EncryptOne()
		} else {
			row[i] = pk.EncryptZero()
		}
	}

	for i := 0; i < dimWidth; i++ {
		if i == colIndex {
			col[i] = pk.EncryptOneAtLevel(paillier.EncLevelTwo)
		} else {
			col[i] = pk.EncryptZeroAtLevel(paillier.EncLevelTwo)
		}
	}

	return &DoublyEncryptedQuery{
		Pk:       pk,
		EBitsRow: row,
		EBitsCol: col,
	}
}

// Recover combines shares of slots to recover the data
func Recover(resShares []*SecretSharedQueryResult) []*Slot {

	numSlots := len(resShares[0].Shares)
	res := make([]*Slot, numSlots)

	// init the slots with the correct size
	for i := 0; i < numSlots; i++ {
		res[i] = &Slot{
			Data: make([]byte, resShares[0].SlotBytes),
		}
	}

	for i := 0; i < len(resShares); i++ {
		for j := 0; j < numSlots; j++ {
			XorSlots(res[j], resShares[i].Shares[j])
		}
	}

	return res
}

// RecoverEncrypted decryptes the encrypted slot and returns slot
func RecoverEncrypted(res *EncryptedQueryResult, sk *paillier.SecretKey) []*Slot {

	slots := make([]*Slot, len(res.Slots))

	// iterate over all the encrypted slots
	for i, eslot := range res.Slots {
		arr := make([]*big.Int, len(eslot.Cts))
		for j, ct := range eslot.Cts {
			arr[j] = paillier.ToBigInt(sk.Decrypt(ct))
		}

		slots[i] = NewSlotFromBigIntArray(arr, res.SlotBytes, res.NumBytesPerCiphertext)
	}

	return slots
}

// RecoverDoublyEncrypted decryptes the encrypted slot and returns slot
func RecoverDoublyEncrypted(res *DoublyEncryptedQueryResult, sk *paillier.SecretKey) *Slot {

	ciphertexts := make([]*paillier.Ciphertext, len(res.Slot.Cts))
	for i, ct := range res.Slot.Cts {

		// TODO: modify paillier to make this process cleaner
		ctValue := sk.Decrypt(ct)
		ct := &paillier.Ciphertext{C: ctValue, Level: paillier.EncLevelOne}
		ciphertexts[i] = ct
	}

	arr := make([]*big.Int, len(ciphertexts))
	for j, c := range ciphertexts {
		arr[j] = paillier.ToBigInt(sk.Decrypt(c))
	}

	slot := NewSlotFromBigIntArray(arr, res.SlotBytes, res.NumBytesPerCiphertext)

	return slot
}

func randomBits(n int) []bool {

	bits := make([]bool, n)
	for i := 0; i < n; i++ {
		if rand.Intn(2) == 1 {
			bits[i] = true
		} else {
			bits[i] = false
		}
	}

	return bits
}
