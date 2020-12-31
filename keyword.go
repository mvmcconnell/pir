package pir

import (
	"errors"
	"math"
)

// padding value to encode when formatting the database for PIR
const padding = "x"

// PrivateSqrtST is a search tree structure with sqrt nodes per layer.
// Requires 1 PIR query to get the index
// First round: get FirstLayer (sqrt N boundries)
// Second round: PIR query (sqrt N boundries)
// This is optimal in when the boundries are small
// but PrivateBST gets better asymptotic bandwidth
type PrivateSqrtST struct {
	FirstLayer  []string
	SecondLayer *Database
	NumKeys     int
	SlotBytes   int
	Width       int
	Height      int
}

// NewPrivateSqrtST returns an empty PrivateBST struct
func NewPrivateSqrtST() *PrivateSqrtST {
	return &PrivateSqrtST{}
}

// BuildForData first generates a PrivateSqrtST for the data
// and then converts one layer into a PIR database
// with optimal width/height
func (sqst *PrivateSqrtST) BuildForData(data []string) error {

	// make sure data is sorted
	for i := range data {
		if i+1 >= len(data) {
			break
		}
		if data[i] > data[i+1] {
			return errors.New("data not sorted")
		}
	}

	// check if the data size has an integer sqrt and make it so if not
	if math.Sqrt(float64(len(data))) != math.Floor(math.Sqrt(float64(len(data)))) {
		data = PadToPowerOf2(data)
	}

	sqrtDim := int(math.Sqrt(float64(len(data))))

	firstLayeBoundries := make([]string, 0)
	for i := sqrtDim; i < len(data); i += sqrtDim {
		firstLayeBoundries = append(firstLayeBoundries, data[i])
	}
	firstLayeBoundries = append(firstLayeBoundries, data[len(data)-1])

	slotBytes := GetRequiredSlotSize(firstLayeBoundries)

	db := NewDatabase()
	slotSize := GetRequiredSlotSize(data)
	db.BuildForDataWithSlotSize(data, slotSize)

	sqst.FirstLayer = firstLayeBoundries
	sqst.SecondLayer = db
	sqst.SlotBytes = slotBytes
	sqst.NumKeys = len(data)
	sqst.Width = sqrtDim
	sqst.Height = sqrtDim

	return nil
}

// PrivateQuery queries the specified layer of the BST using PIR
func (sqst *PrivateSqrtST) PrivateQuery(
	query *QueryShare,
	nprocs int) (*SecretSharedQueryResult, error) {

	return sqst.SecondLayer.PrivateSecretSharedQuery(query, nprocs)
}

// PrivateEncryptedQuery queries the specified layer of the BST using cPIR
func (sqst *PrivateSqrtST) PrivateEncryptedQuery(
	query *EncryptedQuery,
	nprocs int) (*EncryptedQueryResult, error) {

	return sqst.SecondLayer.PrivateEncryptedQuery(query, nprocs)
}

// GetSecondLayerMetadata returns the metadata for PIR database of the second layer
func (sqst *PrivateSqrtST) GetSecondLayerMetadata() *DBMetadata {
	return &DBMetadata{
		sqst.SecondLayer.SlotBytes,
		sqst.SecondLayer.DBSize,
	}
}

// PadToPowerOf2 pads the data to a power of 2
func PadToPowerOf2(data []string) []string {

	nextPower := int(math.Pow(2, math.Ceil(math.Log2(float64(len(data))))))
	newdata := make([]string, nextPower)
	for i := 0; i < nextPower; i++ {
		if i < len(data) {
			newdata[i] = data[i]
		} else {
			newdata[i] = padding
		}
	}

	return newdata
}

// PadToSqrt pads the data such that sqrt(N) is an sinteger
func PadToSqrt(data []string) []string {

	nextSqrt := int(math.Ceil(math.Sqrt(float64(len(data)))))
	nextSqrt = nextSqrt * nextSqrt

	newdata := make([]string, nextSqrt)
	for i := 0; i < nextSqrt; i++ {
		if i < len(data) {
			newdata[i] = data[i]
		} else {
			newdata[i] = padding
		}
	}

	return newdata
}
