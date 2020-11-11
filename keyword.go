package pir

import (
	"math"
	"sort"
)

// padding value to encode when formatting the database for PIR
const padding = "x"

// PrivateBST is a binary search index structure
// to find an index of a keyword using recursive PIR
// to query each layer of the tree.
// Requires log(n) PIR queries to go through the layers
// Each layer is a PIR database
type PrivateBST struct {
	Root      *Slot
	Layers    []*Database // each layer is a list of  2^i (i > 0) values representing the ith layer of the tree
	NumKeys   int
	SlotBytes int
}

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

// NewPrivateBST returns an empty PrivateBST struct
func NewPrivateBST() *PrivateBST {
	return &PrivateBST{}
}

// NewPrivateSqrtST returns an empty PrivateBST struct
func NewPrivateSqrtST() *PrivateSqrtST {
	return &PrivateSqrtST{}
}

// BuildForData first generates a BST for the data
// and then converts each layer into a PIR database
// with optimal width/height
func (bst *PrivateBST) BuildForData(data []string) error {

	// check if the data size is a power of 2
	// this is a requirement for constructing the BST
	if math.Log2(float64(len(data))) != math.Floor(math.Log2(float64(len(data)))) {
		data = PadToPowerOf2(data)
	}

	bst.NumKeys = len(data)

	// get depth of tree
	depth := int(math.Ceil(math.Log2(float64(len(data)))))

	// recursively build the BST
	layers, _ := buildBST(data, depth)

	// build PIR databases over each layer of the BST
	bst.Layers = make([]*Database, depth)

	slotBytes := GetRequiredSlotSize(data)

	for i := 0; i < depth; i++ {

		bst.Layers[i] = NewDatabase()

		// layer index is offset by 1 given we do not include root
		bst.Layers[i].BuildForDataWithSlotSize(layers[i], slotBytes)
	}

	bst.Root = NewSlotFromString(layers[0][0], slotBytes)
	bst.SlotBytes = slotBytes

	return nil
}

// BuildForData first generates a PrivateSqrtST for the data
// and then converts one layer into a PIR database
// with optimal width/height
func (sqst *PrivateSqrtST) BuildForData(data []string) error {

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
func (bst *PrivateBST) PrivateQuery(
	query *QueryShare,
	layer int,
	nprocs int) (*SecretSharedQueryResult, error) {

	return bst.Layers[layer].PrivateSecretSharedQuery(query, nprocs)
}

// PrivateEncryptedQuery queries the specified layer of the BST using cPIR
func (bst *PrivateBST) PrivateEncryptedQuery(
	query *EncryptedQuery,
	layer int,
	nprocs int) (*EncryptedQueryResult, error) {

	return bst.Layers[layer].PrivateEncryptedQuery(query, nprocs)
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

// GetLayerMetadata returns the metadata for each PIR database of each layer
func (bst *PrivateBST) GetLayerMetadata() []*DBMetadata {
	layerMetadata := make([]*DBMetadata, len(bst.Layers))

	for i, db := range bst.Layers {
		layerMetadata[i] = &DBMetadata{
			db.SlotBytes,
			db.DBSize,
		}
	}

	return layerMetadata
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

// returns (layers, boundries)
// layers does not include values from previous layers
// boundries includes all values at the layer
func buildBST(data []string, depth int) ([][]string, [][]string) {

	// sort the strings
	sort.Strings(data)

	// TODO: make this function more elegant. It's a bit of a hack right now.
	// Technically, all this function needs to do is extract the binary search tree
	// boundries and place them into an array (one array per layer)
	// This might be better to do recursively.

	allBoundries := make(map[int]bool)
	layers := make([][]string, depth)
	boundries := make([][]string, depth)

	layerIndex := 0
	step := len(data) / 2 // len(data) is a power of two

	numProcessed := 0
	for i := depth - 1; i >= 0; i-- {
		layers[layerIndex] = make([]string, 0)
		boundries[layerIndex] = make([]string, 0)

		// example with len(data) = 64
		//                                32
		//                16             [32]             48
		//         8     [16]     24     [32]     40     [48]     56
		//     4  [8] 12 [16] 20 [24] 28 [32] 36 [40] 44 [48] 52 [56] 60
		// etc...

		num := int(math.Pow(2, float64(layerIndex))) + numProcessed
		nextIndex := step
		for j := 0; j < num; j++ {
			boundries[layerIndex] = append(boundries[layerIndex], data[nextIndex])

			if exists, _ := allBoundries[nextIndex]; !exists {
				layers[layerIndex] = append(layers[layerIndex], data[nextIndex])
				allBoundries[nextIndex] = true
				numProcessed++
			}

			nextIndex += step
		}

		step /= 2
		layerIndex++
	}

	return layers, boundries
}
