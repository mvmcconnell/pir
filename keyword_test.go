package pir

import (
	"math"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const NumTrials int = 10 // number of times to run some of the tests

func generateStringsInSequence(n int) []string {

	strings := make([]string, n)

	for i := range strings {
		strings[i] = strconv.Itoa(i)
	}

	return strings
}

// executes a query over the KNN data structure.
// run with 'go test -v -run TestQuery' to see log outputs.
func TestBuild(t *testing.T) {
	setup()

	strings := generateStringsInSequence(100)

	// build binary search tree keyword index
	bst := NewPrivateBST()
	bst.BuildForData(strings)

	// build sqrt search tree keyword index
	sqst := NewPrivateSqrtST()
	sqst.BuildForData(strings)
}

func TestBuildBST(t *testing.T) {
	setup()

	for trial := 0; trial < NumTrials; trial++ {

		numStrings := rand.Intn(1<<10) + 100

		data := generateStringsInSequence(numStrings)
		data = PadToPowerOf2(data)
		layers, _ := buildBST(data, int(math.Ceil(math.Log2(float64(len(data))))))

		if len(layers[0]) != 1 {
			t.Fatalf("Expected %v element in layer %v; got %v\n", 1, 0, len(layers[0]))
		}
		numTotal := 0
		for i := 1; i < len(layers); i++ {
			expected := int(math.Pow(2, float64(i)))
			if len(layers[i]) != expected {
				t.Fatalf("Expected %v elements in layer %v; got %v\n", expected, i, len(layers[i]))
			}

			numTotal += expected
		}

		orderOk := true
		lastLayer := len(layers) - 1
		for i := 0; i < len(layers[lastLayer])-1; i++ {
			if strings.Compare(layers[lastLayer][i], layers[lastLayer][i+1]) >= 1 {
				t.Logf("Wrong order \"%v\" > \"%v\"\n", layers[lastLayer][i], layers[lastLayer][i+1])
				orderOk = false
				break
			}
		}

		if !orderOk {
			t.Fatalf("order is wrong\n")

		}
	}
}

// func TestKeywordQueryBST(t *testing.T) {
// 	setup()

// 	for trial := 0; trial < NumTrials; trial++ {

// 		numStrings := rand.Intn(1<<10) + 100
// 		data := generateStringsInSequence(numStrings)
// 		paddingSize := len(PadToPowerOf2(data)) - len(data)

// 		data = PadToPowerOf2(data)
// 		sort.Strings(data)

// 		bst := NewPrivateBST()
// 		bst.BuildForData(data)

// 		t.Logf("[Test]: padding size is %v.\n", paddingSize)

// 		var res []*Slot

// 		for i := 0; i < len(data); i++ {

// 			query := NewSlotFromString(data[i], bst.SlotBytes)

// 			depth := len(bst.Layers)
// 			boundry := bst.Root

// 			// index of the value
// 			index := len(data) / 2

// 			// next index increment (left or right)
// 			step := len(data) / 4

// 			// index of the next boundry in the tree
// 			boundryIndex := 0

// 			for j := 1; j <= depth; j++ {

// 				// index of the current boundry (+1) in the next layer
// 				// i.e., this is the upper value to compare to
// 				boundryIndex = (index / step) / 2

// 				cmp := query.Compare(boundry)
// 				if cmp > 0 {
// 					t.Logf("[Test]: query %v, index %v,  boundry index %v, boundry %v, going right.\n", query, index, boundryIndex, boundry)
// 					index += step
// 				} else if cmp < 0 {
// 					t.Logf("[Test]: query %v, index %v, boundry index %v, boundry %v, going left.\n", query, index, boundryIndex, boundry)
// 					boundryIndex--
// 					index -= step
// 				} else {
// 					break //  query == boundry
// 				}

// 				// no more boundries to fetch
// 				if j == depth {
// 					break
// 				}

// 				step /= 2
// 				if step == 0 {
// 					step = 1
// 				}

// 				rowIndex, colIndex := bst.Layers[j].IndexToCoordinates(boundryIndex, dimWidth, dimHeight)
// 				shares := bst.Layers[j].NewIndexQueryShares(uint(rowIndex), 2)

// 				t.Logf("querying layer %v index  %v\n", j, rowIndex)
// 				resA, err := bst.PrivateQuery(shares[0], j, NumProcsForQuery)
// 				if err != nil {
// 					t.Fail()
// 				}
// 				resB, err := bst.PrivateQuery(shares[1], j, NumProcsForQuery)
// 				if err != nil {
// 					t.Fail()
// 				}

// 				resultShares := [...]*SecretSharedQueryResult{resA, resB}
// 				res = Recover(resultShares[:])
// 				boundry = res[colIndex]
// 			}

// 			if index != i && data[index] != data[i] {
// 				t.Fatalf("Incorrect index %v, expected %v; Data at index %v, expected data %v\n", index, i, data[index], data[i])
// 			} else {
// 				t.Log("passed")
// 			}
// 		}
// 	}
// }

func TestKeywordQuerySqrtST(t *testing.T) {
	setup()

	for trial := 0; trial < NumTrials; trial++ {

		numStrings := rand.Intn(1<<10) + 100
		data := generateStringsInSequence(numStrings)

		data = PadToSqrt(data)
		sort.Strings(data)

		t.Logf("[Test]: data size %v\n", len(data))

		sqst := NewPrivateSqrtST()
		sqst.BuildForData(data)

		var res []*Slot

		for i := 0; i < len(data); i++ {

			query := NewSlotFromString(data[i], sqst.SlotBytes)

			if int(math.Ceil(math.Sqrt(float64(len(data))))) != len(sqst.FirstLayer) {
				t.Fatalf("First layer does not have the correct size. Expected: %v Actual %v\n",
					int(math.Sqrt(float64(len(data)))),
					len(sqst.FirstLayer),
				)
			}

			boundry := ""
			rowIndex := 0
			for rowIndex, boundry = range sqst.FirstLayer {
				if data[i] < boundry {
					break
				}
			}

			shares := sqst.SecondLayer.NewIndexQueryShares(uint(rowIndex), sqst.Height, 2)

			resA, err := sqst.PrivateQuery(shares[0], NumProcsForQuery)
			if err != nil {
				t.Fail()
			}
			resB, err := sqst.PrivateQuery(shares[1], NumProcsForQuery)
			if err != nil {
				t.Fail()
			}

			resultShares := [...]*SecretSharedQueryResult{resA, resB}
			res = Recover(resultShares[:])

			if len(res) != len(sqst.FirstLayer) {
				t.Fatalf("Second layer does not have the correct size. Expected: %v Actual %v\n",
					len(res),
					len(sqst.FirstLayer),
				)
			}

			colIndex := 0
			var slot *Slot
			for colIndex, slot = range res {
				if slot.Compare(query) >= 0 {
					break
				}
			}

			index := rowIndex*sqst.Width + colIndex

			if index != i && data[index] != data[i] {
				t.Fatalf("Incorrect index %v, expected %v; Data at index %v, expected data %v\n", index, i, data[index], data[i])
			}
		}
	}
}
