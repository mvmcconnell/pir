package pir

import (
	"math/big"
	"math/rand"

	he "github.com/sachaservan/hewrap"
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
}

// EncryptedQuery is an encryption of a point function
// that evaluates to 1 at the desired row in the database
// bits = (0, 0,.., 1, ...0, 0)
type EncryptedQuery struct {
	Pk    *he.PublicKey
	EBits []*he.Ciphertext
}

// DoublyEncryptedQuery consists of two encrypted point functions
// that evaluates to 1 at the desired row and column in the database
type DoublyEncryptedQuery struct {
	Pk       *he.PublicKey
	EBitsRow []*he.Ciphertext
	EBitsCol []*he.Ciphertext
}

// NewQueryShares generates random PIR query shares for the index
func (dbmd *DBMetadata) NewQueryShares(keyword uint, numShares uint) []*QueryShare {

	// num bits to represent the index
	numBits := uint(32)

	pf := ClientInitialize(numBits)

	var dpfKeysTwoParty []*Key2P
	var dpfKeysMultiParty []*KeyMP

	if numShares == 2 {
		dpfKeysTwoParty = pf.GenerateTwoServer(keyword, 1)
	} else {
		dpfKeysMultiParty = pf.GenerateMultiServer(keyword, 1, numShares)
	}

	shares := make([]*QueryShare, numShares)
	for i := 0; i < int(numShares); i++ {
		shares[i] = &QueryShare{}
		shares[i].ShareNumber = uint(i)
		shares[i].PrfKeys = pf.PrfKeys

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
func (dbmd *DBMetadata) NewEncryptedQuery(pk *he.PublicKey, index int) *EncryptedQuery {

	res := make([]*he.Ciphertext, dbmd.Height)
	for i := 0; i < dbmd.Height; i++ {
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
func (dbmd *DBMetadata) NewDoublyEncryptedQuery(pk *he.PublicKey, rowIndex, colIndex int) *DoublyEncryptedQuery {

	row := make([]*he.Ciphertext, dbmd.Height)
	col := make([]*he.Ciphertext, dbmd.Width)
	for i := 0; i < dbmd.Height; i++ {
		if i == rowIndex {
			row[i] = pk.EncryptOne()
		} else {
			row[i] = pk.EncryptZero()
		}
	}

	for i := 0; i < dbmd.Width; i++ {
		if i == colIndex {
			col[i] = pk.EncryptOne()
		} else {
			col[i] = pk.EncryptZero()
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
func RecoverEncrypted(res *EncryptedQueryResult, sk *he.SecretKey) []*Slot {

	slots := make([]*Slot, len(res.Slots))

	// iterate over all the encrypted slots
	for i, eslot := range res.Slots {
		arr := make([]*big.Int, len(eslot.Cts))
		for j, c := range eslot.Cts {
			arr[j] = sk.Decrypt(res.Pk, c)
		}

		slots[i] = NewSlotFromBigIntArray(arr, res.SlotBytes, res.NumBytesPerCiphertext)
	}

	return slots
}

// RecoverDoublyEncrypted decryptes the encrypted slot and returns slot
func RecoverDoublyEncrypted(res *DoublyEncryptedQueryResult, sk *he.SecretKey) *Slot {

	ciphertexts := make([]*he.Ciphertext, len(res.Slot.Cts))
	for i, cts := range res.Slot.Cts {

		arr := make([]*big.Int, len(cts))

		for j, ct := range cts {
			arr[j] = sk.Decrypt(res.Pk, ct)
		}

		b, _ := cts[0].Bytes()
		ctslot := NewSlotFromBigIntArray(arr, len(b), res.NumBytesPerEncryptedCiphertext)

		// recover the ciphertext from the bytes
		ct, err := res.Pk.NewCiphertextFromBytes(ctslot.Data)
		if err != nil {
			panic(err)
		}
		ciphertexts[i] = ct
	}

	arr := make([]*big.Int, len(ciphertexts))
	for j, c := range ciphertexts {
		arr[j] = sk.Decrypt(res.Pk, c)
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
