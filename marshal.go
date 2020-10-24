package pir

// import (
// 	"bytes"
// 	"encoding/gob"

// 	"github.com/sachaservan/paillier"
// )

// type doublyEyncryptedQueryMarshalWrapper struct {
// 	Pk            *paillier.PublicKey
// 	EBitsRowBytes [][]byte
// 	EBitsColBytes [][]byte
// }

// type doublyEncryptedResultMarshalWrapper struct {
// 	Pk                    *paillier.PublicKey
// 	CtsBytes              [][][]byte
// 	SlotBytes             int
// 	NumBytesPerCiphertext int
// }

// type encryptedQueryMarshalWrapper struct {
// 	Pk         *paillier.PublicKey
// 	EbitsBytes [][]byte
// }

// type encryptedResultMarshalWrapper struct {
// 	Pk                    *paillier.PublicKey
// 	CtsBytes              [][][]byte
// 	SlotBytes             int
// 	NumBytesPerCiphertext int
// }

// // MarshalBinary is needed in order to encode/decode
// // ciphertexts type since (for now) ciphertext
// // can only be converted to bytes and back
// func (res *EncryptedQueryResult) MarshalBinary() ([]byte, error) {

// 	if res == nil {
// 		return nil, nil
// 	}

// 	ctsBytes := make([][][]byte, 0)
// 	for i, slot := range res.Slots {
// 		ctsBytes = append(ctsBytes, make([][]byte, 0))
// 		for _, ct := range slot.Cts {
// 			bytes, _ := ct.Bytes()
// 			ctsBytes[i] = append(ctsBytes[i], bytes)
// 		}
// 	}

// 	// wrap struct
// 	w := encryptedResultMarshalWrapper{
// 		Pk:                    res.Pk,
// 		CtsBytes:              ctsBytes,
// 		SlotBytes:             res.SlotBytes,
// 		NumBytesPerCiphertext: res.NumBytesPerCiphertext,
// 	}

// 	// use default gob encoder
// 	var buf bytes.Buffer
// 	enc := gob.NewEncoder(&buf)
// 	if err := enc.Encode(w); err != nil {
// 		return nil, err
// 	}
// 	return buf.Bytes(), nil
// }

// // UnmarshalBinary is needed in order to encode/decode
// // ciphertexts type since (for now) ciphertext
// // can only be converted to bytes and back
// func (res *EncryptedQueryResult) UnmarshalBinary(data []byte) error {

// 	if len(data) == 0 {
// 		return nil
// 	}

// 	w := encryptedResultMarshalWrapper{}

// 	reader := bytes.NewReader(data)
// 	dec := gob.NewDecoder(reader)
// 	if err := dec.Decode(&w); err != nil {
// 		return err
// 	}

// 	res.Slots = make([]*EncryptedSlot, len(w.CtsBytes))
// 	for i, slot := range w.CtsBytes {
// 		cts := make([]*paillier.Ciphertext, 0)
// 		for _, bytes := range slot {
// 			ct, _ := w.Pk.NewCiphertextFromBytes(bytes)
// 			cts = append(cts, ct)
// 		}

// 		res.Slots[i] = &EncryptedSlot{cts}
// 	}

// 	res.Pk = w.Pk
// 	res.NumBytesPerCiphertext = w.NumBytesPerCiphertext
// 	res.SlotBytes = w.SlotBytes

// 	return nil
// }

// // MarshalBinary is needed in order to encode/decode
// // ciphertexts type since (for now) ciphertext
// // can only be converted to bytes and back
// func (res *DoublyEncryptedQueryResult) MarshalBinary() ([]byte, error) {

// 	if res == nil {
// 		return nil, nil
// 	}

// 	ctsBytes := make([][][]byte, 0)
// 	ctsBytes = append(ctsBytes, make([][]byte, 0))
// 	for i, ctArr := range res.Slot.Cts {
// 		for _, ct := range ctArr {
// 			bytes, _ := ct.Bytes()
// 			ctsBytes[i] = append(ctsBytes[i], bytes)
// 		}
// 	}

// 	// wrap struct
// 	w := doublyEncryptedResultMarshalWrapper{
// 		Pk:                    res.Pk,
// 		CtsBytes:              ctsBytes,
// 		SlotBytes:             res.SlotBytes,
// 		NumBytesPerCiphertext: res.NumBytesPerCiphertext,
// 	}

// 	// use default gob encoder
// 	var buf bytes.Buffer
// 	enc := gob.NewEncoder(&buf)
// 	if err := enc.Encode(w); err != nil {
// 		return nil, err
// 	}
// 	return buf.Bytes(), nil
// }

// // UnmarshalBinary is needed in order to encode/decode
// // ciphertexts type since (for now) ciphertext
// // can only be converted to bytes and back
// func (res *DoublyEncryptedQueryResult) UnmarshalBinary(data []byte) error {

// 	if len(data) == 0 {
// 		return nil
// 	}

// 	w := encryptedResultMarshalWrapper{}

// 	reader := bytes.NewReader(data)
// 	dec := gob.NewDecoder(reader)
// 	if err := dec.Decode(&w); err != nil {
// 		return err
// 	}

// 	ctsArr := make([][]*paillier.Ciphertext, 0)

// 	for _, ctArrBytes := range w.CtsBytes {
// 		cts := make([]*paillier.Ciphertext, 0)
// 		for _, bytes := range ctArrBytes {
// 			ct, _ := w.Pk.NewCiphertextFromBytes(bytes)
// 			cts = append(cts, ct)
// 		}

// 		ctsArr = append(ctsArr, cts)
// 	}

// 	slot := &DoublyEncryptedSlot{
// 		Cts: ctsArr,
// 	}

// 	res.Pk = w.Pk
// 	res.NumBytesPerCiphertext = w.NumBytesPerCiphertext
// 	res.SlotBytes = w.SlotBytes
// 	res.Slot = slot

// 	return nil
// }

// // MarshalBinary is needed in order to encode/decode
// // ciphertexts type since (for now) ciphertext
// // can only be converted to bytes and back
// func (q *EncryptedQuery) MarshalBinary() ([]byte, error) {

// 	if q == nil {
// 		return nil, nil
// 	}

// 	ebitsBytes := make([][]byte, 0)
// 	for _, ct := range q.EBits {
// 		bytes, _ := ct.Bytes()
// 		ebitsBytes = append(ebitsBytes, bytes)
// 	}

// 	// wrap struct
// 	w := encryptedQueryMarshalWrapper{
// 		Pk:         q.Pk,
// 		EbitsBytes: ebitsBytes,
// 	}

// 	// use default gob encoder
// 	var buf bytes.Buffer
// 	enc := gob.NewEncoder(&buf)
// 	if err := enc.Encode(w); err != nil {
// 		return nil, err
// 	}
// 	return buf.Bytes(), nil
// }

// // UnmarshalBinary is needed in order to encode/decode
// // ciphertexts type since (for now) ciphertext
// // can only be converted to bytes and back
// func (q *EncryptedQuery) UnmarshalBinary(data []byte) error {

// 	if len(data) == 0 {
// 		return nil
// 	}

// 	w := encryptedQueryMarshalWrapper{}

// 	reader := bytes.NewReader(data)
// 	dec := gob.NewDecoder(reader)
// 	if err := dec.Decode(&w); err != nil {
// 		return err
// 	}

// 	ebits := make([]*paillier.Ciphertext, 0)
// 	for _, bytes := range w.EbitsBytes {
// 		ct, _ := w.Pk.NewCiphertextFromBytes(bytes)
// 		ebits = append(ebits, ct)
// 	}

// 	q.Pk = w.Pk
// 	q.EBits = ebits

// 	return nil
// }

// // MarshalBinary is needed in order to encode/decode
// // ciphertexts type since (for now) ciphertext
// // can only be converted to bytes and back
// func (q *DoublyEncryptedQuery) MarshalBinary() ([]byte, error) {

// 	if q == nil {
// 		return nil, nil
// 	}

// 	ebitsRowBytes := make([][]byte, 0)
// 	for _, ct := range q.EBitsRow {
// 		bytes, _ := ct.Bytes()
// 		ebitsRowBytes = append(ebitsRowBytes, bytes)
// 	}

// 	ebitsColBytes := make([][]byte, 0)
// 	for _, ct := range q.EBitsRow {
// 		bytes, _ := ct.Bytes()
// 		ebitsColBytes = append(ebitsColBytes, bytes)
// 	}

// 	// wrap struct
// 	w := doublyEyncryptedQueryMarshalWrapper{
// 		Pk:            q.Pk,
// 		EBitsRowBytes: ebitsRowBytes,
// 		EBitsColBytes: ebitsColBytes,
// 	}

// 	// use default gob encoder
// 	var buf bytes.Buffer
// 	enc := gob.NewEncoder(&buf)
// 	if err := enc.Encode(w); err != nil {
// 		return nil, err
// 	}
// 	return buf.Bytes(), nil
// }

// // UnmarshalBinary is needed in order to encode/decode
// // ciphertexts type since (for now) ciphertext
// // can only be converted to bytes and back
// func (q *DoublyEncryptedQuery) UnmarshalBinary(data []byte) error {

// 	if len(data) == 0 {
// 		return nil
// 	}

// 	w := doublyEyncryptedQueryMarshalWrapper{}

// 	reader := bytes.NewReader(data)
// 	dec := gob.NewDecoder(reader)
// 	if err := dec.Decode(&w); err != nil {
// 		return err
// 	}

// 	ebitsRow := make([]*paillier.Ciphertext, 0)
// 	for _, bytes := range w.EBitsRowBytes {
// 		ct, _ := w.Pk.NewCiphertextFromBytes(bytes)
// 		ebitsRow = append(ebitsRow, ct)
// 	}

// 	ebitsCol := make([]*paillier.Ciphertext, 0)
// 	for _, bytes := range w.EBitsColBytes {
// 		ct, _ := w.Pk.NewCiphertextFromBytes(bytes)
// 		ebitsRow = append(ebitsRow, ct)
// 	}

// 	q.Pk = w.Pk
// 	q.EBitsRow = ebitsRow
// 	q.EBitsCol = ebitsCol

// 	return nil
// }
