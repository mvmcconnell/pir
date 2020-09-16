package dpf

// This file contains all the client code for the FSS scheme.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"math"
)

// Initialize client with this function
// numBits represents the input domain for the function, i.e. the number
// of bits to check
func ClientInitialize(numBits uint) *Dpf {
	f := new(Dpf)
	f.NumBits = numBits
	f.PrfKeys = make([]*PrfKey, initPRFLen)
	// Create fixed AES blocks
	f.FixedBlocks = make([]cipher.Block, initPRFLen)
	for i := uint(0); i < initPRFLen; i++ {
		f.PrfKeys[i] = &PrfKey{}
		f.PrfKeys[i].Bytes = make([]byte, aes.BlockSize)

		rand.Read(f.PrfKeys[i].Bytes)
		//fmt.Println("client")
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
	f.M = 4 // Default is 4. Only used in multiparty. To change this, you should change the size of the CW in multiparty keys. Read comments there.
	f.Temp = make([]byte, aes.BlockSize)
	f.Out = make([]byte, aes.BlockSize*initPRFLen)

	return f
}

// This is based on the following paper:
// Boyle, Elette, Niv Gilboa, and Yuval Ishai. "Function Secret Sharing: Improvements and Extensions." Proceedings of the 2016 ACM SIGSAC Conference on Computer and Communications Security. ACM, 2016.

// Generate Keys for 2-party point functions
// It creates keys for a function that evaluates to b when input x = a.

func (f *Dpf) GenerateTwoServer(a, b uint) []*Key2P {
	fssKeys := make([]*Key2P, 2)
	// Set up initial values
	tempRand1 := make([]byte, aes.BlockSize+1)
	rand.Read(tempRand1)
	fssKeys[0] = &Key2P{}
	fssKeys[0].SInit = tempRand1[:aes.BlockSize]
	fssKeys[0].TInit = tempRand1[aes.BlockSize] % 2

	fssKeys[1] = &Key2P{}
	fssKeys[1].SInit = make([]byte, aes.BlockSize)
	rand.Read(fssKeys[1].SInit)
	fssKeys[1].TInit = fssKeys[0].TInit ^ 1

	// Set current seed being used
	sCurr0 := make([]byte, aes.BlockSize)
	sCurr1 := make([]byte, aes.BlockSize)
	copy(sCurr0, fssKeys[0].SInit)
	copy(sCurr1, fssKeys[1].SInit)
	tCurr0 := fssKeys[0].TInit
	tCurr1 := fssKeys[1].TInit

	// Initialize correction words in FSS keys
	fssKeys[0].CW = make([][]byte, f.NumBits)
	fssKeys[1].CW = make([][]byte, f.NumBits)
	for i := uint(0); i < f.NumBits; i++ {
		// make AES block size + 2 bytes
		fssKeys[0].CW[i] = make([]byte, aes.BlockSize+2)
		fssKeys[1].CW[i] = make([]byte, aes.BlockSize+2)
	}

	leftStart := 0
	rightStart := aes.BlockSize + 1
	for i := uint(0); i < f.NumBits; i++ {
		// "expand" seed into two seeds + 2 bits
		prf(sCurr0, f.FixedBlocks, 3, f.Temp, f.Out)
		prfOut0 := make([]byte, aes.BlockSize*3)
		copy(prfOut0, f.Out[:aes.BlockSize*3])
		prf(sCurr1, f.FixedBlocks, 3, f.Temp, f.Out)
		prfOut1 := make([]byte, aes.BlockSize*3)
		copy(prfOut1, f.Out[:aes.BlockSize*3])

		//fmt.Println(i, sCurr0)
		//fmt.Println(i, sCurr1)
		// Parse out "t" bits
		t0Left := prfOut0[aes.BlockSize] % 2
		t0Right := prfOut0[(aes.BlockSize*2)+1] % 2
		t1Left := prfOut1[aes.BlockSize] % 2
		t1Right := prfOut1[(aes.BlockSize*2)+1] % 2
		// Find bit in a
		aBit := getBit(a, (f.N - f.NumBits + i + 1), f.N)

		// Figure out which half of expanded seeds to keep and lose
		keep := rightStart
		lose := leftStart
		if aBit == 0 {
			keep = leftStart
			lose = rightStart
		}
		//fmt.Println("keep", keep)
		//fmt.Println("aBit", aBit)
		// Set correction words for both keys. Note: they are the same
		for j := 0; j < aes.BlockSize; j++ {
			fssKeys[0].CW[i][j] = prfOut0[lose+j] ^ prfOut1[lose+j]
			fssKeys[1].CW[i][j] = fssKeys[0].CW[i][j]
		}
		fssKeys[0].CW[i][aes.BlockSize] = t0Left ^ t1Left ^ aBit ^ 1
		fssKeys[1].CW[i][aes.BlockSize] = fssKeys[0].CW[i][aes.BlockSize]
		fssKeys[0].CW[i][aes.BlockSize+1] = t0Right ^ t1Right ^ aBit
		fssKeys[1].CW[i][aes.BlockSize+1] = fssKeys[0].CW[i][aes.BlockSize+1]

		for j := 0; j < aes.BlockSize; j++ {
			sCurr0[j] = prfOut0[keep+j] ^ (tCurr0 * fssKeys[0].CW[i][j])
			sCurr1[j] = prfOut1[keep+j] ^ (tCurr1 * fssKeys[0].CW[i][j])
		}
		//fmt.Println("sKeep0:", prfOut0[keep:keep+aes.BlockSize])
		//fmt.Println("sKeep1:", prfOut1[keep:keep+aes.BlockSize])
		tCWKeep := fssKeys[0].CW[i][aes.BlockSize]
		if keep == rightStart {
			tCWKeep = fssKeys[0].CW[i][aes.BlockSize+1]
		}
		tCurr0 = (prfOut0[keep+aes.BlockSize] % 2) ^ tCWKeep*tCurr0
		tCurr1 = (prfOut1[keep+aes.BlockSize] % 2) ^ tCWKeep*tCurr1
	}
	// Convert final CW to integer
	sFinal0, _ := binary.Varint(sCurr0[:8])
	sFinal1, _ := binary.Varint(sCurr1[:8])
	fssKeys[0].FinalCW = (int(b) - int(sFinal0) + int(sFinal1))
	fssKeys[1].FinalCW = fssKeys[0].FinalCW
	if tCurr1 == 1 {
		fssKeys[0].FinalCW = fssKeys[0].FinalCW * -1
		fssKeys[1].FinalCW = fssKeys[0].FinalCW
	}
	return fssKeys
}

func (f Dpf) GenerateMultiServer(a, b, num_p uint) []*KeyMP {

	keys := make([]*KeyMP, num_p)
	p2 := uint(math.Pow(2, float64(num_p-1)))
	mu := uint(math.Ceil(math.Pow(2, float64(f.NumBits)/2) * math.Pow(2, float64(num_p-1)/2.0)))
	v := uint(math.Ceil(math.Pow(2, float64(f.NumBits)) / float64(mu)))

	delta := a & ((1 << (f.NumBits / 2)) - 1)
	gamma := (a & (((1 << (f.NumBits + 1) / 2) - 1) << f.NumBits / 2)) >> f.NumBits / 2
	aArr := make([][][]byte, v)
	for i := uint(0); i < v; i++ {
		aArr[i] = make([][]byte, num_p)
		for j := uint(0); j < num_p; j++ {
			aArr[i][j] = make([]byte, p2)
		}
	}
	for i := uint(0); i < v; i++ {
		for j := uint(0); j < num_p; j++ {
			if j != (num_p - 1) {
				rand.Read(aArr[i][j])
				for k := uint(0); k < p2; k++ {
					aArr[i][j][k] = aArr[i][j][k] % 2
				}
			} else {
				for k := uint(0); k < p2; k++ {
					curr_bits := uint(0)
					for l := uint(0); l < num_p-1; l++ {
						curr_bits += uint(aArr[i][l][k])
					}
					curr_bits = curr_bits % 2
					if i != gamma {
						if curr_bits == 0 {
							aArr[i][j][k] = 0
						} else {
							aArr[i][j][k] = 1
						}
					} else {
						if curr_bits == 0 {
							aArr[i][j][k] = 1
						} else {
							aArr[i][j][k] = 0
						}
					}
				}
			}
		}
	}

	s := make([][][]byte, v)
	for i := uint(0); i < v; i++ {
		s[i] = make([][]byte, p2)
		for j := uint(0); j < p2; j++ {
			s[i][j] = make([]byte, aes.BlockSize)
			rand.Read(s[i][j])
		}
	}

	cw := make([][]uint32, p2)
	cw_temp := make([]uint32, mu)
	cw_helper := make([]byte, f.M*mu)
	numBlocks := uint(math.Ceil(float64(f.M*mu) / float64(aes.BlockSize)))
	// Create correction words
	for i := uint(0); i < p2; i++ {
		prf(s[gamma][i], f.FixedBlocks, numBlocks, f.Temp, f.Out)
		for k := uint(0); k < mu; k++ {
			tempInt := binary.LittleEndian.Uint32(f.Out[f.M*k : f.M*k+f.M])
			cw_temp[k] = cw_temp[k] ^ tempInt
		}
		cw[i] = make([]uint32, mu)
		// The last CW has to fulfill a certain condition, so we deal with it separately
		if i == (p2 - 1) {
			break
		}
		rand.Read(cw_helper)
		for j := uint(0); j < mu; j++ {
			cw[i][j] = binary.LittleEndian.Uint32(cw_helper[f.M*j : f.M*j+f.M])
			cw_temp[j] = cw_temp[j] ^ cw[i][j]
		}
	}

	for i := uint(0); i < mu; i++ {
		if i == delta {
			cw[p2-1][i] = uint32(b) ^ cw_temp[i]
		} else {
			cw[p2-1][i] = cw_temp[i]
		}
	}

	sigma := make([][][]byte, num_p)
	for i := uint(0); i < num_p; i++ {
		// set number of parties in keys
		sigma[i] = make([][]byte, v)
		for j := uint(0); j < v; j++ {
			sigma[i][j] = make([]byte, aes.BlockSize*p2)
			for k := uint(0); k < p2; k++ {
				// if aArr[j][i][k] == 0, sigma[i][j] should be 0
				if aArr[j][i][k] != 0 {
					copy(sigma[i][j][k*aes.BlockSize:k*aes.BlockSize+aes.BlockSize], s[j][k])
				}
			}
		}
	}

	for i := uint(0); i < num_p; i++ {
		keys[i] = &KeyMP{}
		keys[i].Sigma = sigma[i]
		keys[i].CW = cw
		keys[i].NumParties = num_p
	}
	return keys
}
