// TODO: clean up this code.

package dpf

// This file contains the server side code for the FSS library.
import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"math"
)

// Upon receiving query from client, initialize server with
// this function. The server, unlike the client
// receives prfKeys, so it doesn't need to pick random ones
func ServerInitialize(prfKeys []*PrfKey, numBits uint) *Dpf {
	f := new(Dpf)
	f.NumBits = numBits
	f.PrfKeys = make([]*PrfKey, initPRFLen)
	f.FixedBlocks = make([]cipher.Block, initPRFLen)
	for i := range prfKeys {
		f.PrfKeys[i] = &PrfKey{}
		f.PrfKeys[i].Bytes = make([]byte, aes.BlockSize)
		copy(f.PrfKeys[i].Bytes, prfKeys[i].Bytes)

		//fmt.Println("server")
		//fmt.Println(f.PrfKeys[i])
		block, err := aes.NewCipher(f.PrfKeys[i].Bytes)
		if err != nil {
			panic(err.Error())
		}
		f.FixedBlocks[i] = block
	}
	// Check if int is 32 or 64 bit
	var x uint64 = 1 << 32
	if uint(x) == 0 {
		f.N = 32
	} else {
		f.N = 64
	}
	f.M = 4 // Again default = 4. Look at comments in ClientInitialize to understand this.
	f.Temp = make([]byte, aes.BlockSize)
	f.Out = make([]byte, aes.BlockSize*initPRFLen)

	return f
}

// This is the 2-party FSS evaluation function for point functions.
// This is based on the following paper:
// Boyle, Elette, Niv Gilboa, and Yuval Ishai. "Function Secret Sharing: Improvements and Extensions." Proceedings of the 2016 ACM SIGSAC Conference on Computer and Communications Security. ACM, 2016.

// Each of the 2 server calls this function to evaluate their function
// share on a value. Then, the client adds the results from both servers.

func (f *Dpf) Evaluate2P(serverNum uint, k *Key2P, x uint) int {
	fOut := make([]byte, aes.BlockSize*initPRFLen)
	fTemp := make([]byte, aes.BlockSize)

	sCurr := make([]byte, aes.BlockSize)
	copy(sCurr, k.SInit)
	tCurr := k.TInit
	for i := uint(0); i < f.NumBits; i++ {
		var xBit byte = 0
		if i != f.N {
			xBit = byte(getBit(x, (f.N - f.NumBits + i + 1), f.N))
		}

		prf(sCurr, f.FixedBlocks, 3, fTemp, fOut)
		// fmt.Println(i, sCurr)
		// fmt.Println(i, "f.Out:", fOut)
		// Keep counter to ensure we are accessing CW correctly
		count := 0
		for j := 0; j < aes.BlockSize*2+2; j++ {
			// Make sure we are doing G(s) ^ (t*sCW||tLCW||sCW||tRCW)
			if j == aes.BlockSize+1 {
				count = 0
			} else if j == aes.BlockSize*2+1 {
				count = aes.BlockSize + 1
			}

			fOut[j] = fOut[j] ^ (tCurr * k.CW[i][count])
			count++
		}
		//fmt.Println("xBit", xBit)
		// Pick right seed expansion based on
		if xBit == 0 {
			copy(sCurr, fOut[:aes.BlockSize])
			tCurr = fOut[aes.BlockSize] % 2
		} else {
			copy(sCurr, fOut[(aes.BlockSize+1):(aes.BlockSize*2+1)])
			tCurr = fOut[aes.BlockSize*2+1] % 2
		}
		//fmt.Println(f.Out)
	}
	sFinal, _ := binary.Varint(sCurr[:8])
	if serverNum == 0 {
		return int(sFinal) + int(tCurr)*k.FinalCW
	} else {
		return -1 * (int(sFinal) + int(tCurr)*k.FinalCW)
	}
}

// This function is for multi-party (3 or more parties) FSS
// for equality functions
// The API interface is similar to the 2 party version.
// One main difference is the output of the evaluation function
// is XOR homomorphic, so for additive queries like SUM and COUNT,
// the client has to add it locally.

func (f *Dpf) EvaluateMP(k *KeyMP, x uint) uint32 {

	p2 := uint(math.Pow(2, float64(k.NumParties-1)))
	mu := uint(math.Ceil(math.Pow(2, float64(f.NumBits)/2) * math.Pow(2, float64(k.NumParties-1)/2)))
	numBits := f.NumBits

	delta := x & ((1 << (numBits / 2)) - 1)
	gamma := (x & (((1 << (numBits + 1) / 2) - 1) << numBits / 2)) >> numBits / 2
	mBytes := f.M * mu

	y := make([]uint32, mu)
	for i := uint(0); i < p2; i++ {
		s := k.Sigma[gamma][i*aes.BlockSize : i*aes.BlockSize+aes.BlockSize]
		all_zero_bytes := true
		for j := uint(0); j < aes.BlockSize; j++ {
			if s[j] != 0 {
				all_zero_bytes = false
				break
			}
		}

		if !all_zero_bytes {
			numBlocks := uint(math.Ceil(float64(mBytes) / float64(aes.BlockSize)))
			prf(s, f.FixedBlocks, numBlocks, f.Temp, f.Out)
			for k := uint(0); k < mu; k++ {
				tempInt := binary.LittleEndian.Uint32(f.Out[f.M*k : f.M*k+f.M])
				y[k] = y[k] ^ tempInt
			}
			for j := uint(0); j < mu; j++ {
				y[j] = k.CW[i][j] ^ y[j]
			}
		}
	}
	return y[delta]
}
