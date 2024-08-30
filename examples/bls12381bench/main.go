package main

import (
	"crypto/rand"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core"
	"github.com/holiman/goevmlab/fuzzing"
	"github.com/holiman/goevmlab/ops"
	"github.com/holiman/goevmlab/program"
	"io"
	"math/big"
	"os"
)

func runit() error {
	a := program.NewProgram()

	aAddr := common.HexToAddress("0xff0a")
}

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generateBenchCode(iterCount int, isNoop bool) *program.Program {
	benchCode := program.NewProgram()
	benchCode.CalldataLoad(0)
	benchCode.Op(ops.DUP1)
	benchCode.Push("0xffffffffffffffffffffffffffffffff00000000000000000000000000000000")
	benchCode.Op(ops.AND)
	benchCode.Push(0x80)
	benchCode.Op(ops.SWAP1)
	// stack: calldata[0], input_size

	benchCode.Push("0xffffffffffffffffffffffffffffffff")
	benchCode.Op(ops.AND)
	//stack: output_size, input_size

	benchCode.Push(0x20)
	benchCode.Op(ops.CALLDATALOAD)
	benchCode.Push(0x60)
	benchCode.Op(ops.SHR)
	//stack: precompile_address, output_size, input_size

	benchCode.Push("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00")

	for i := 0; i < iterCount; i++ {
		benchCode.Op(ops.DUP4)
		if isNoop {
			benchCode.Op(ops.DUP4)
			benchCode.Op(ops.DUP2)
			benchCode.Op(ops.DUP7)
			benchCode.Push(0)
			benchCode.Op(ops.DUP7)
			benchCode.Op(ops.GASLIMIT)
			benchCode.Op(ops.STATICCALL)
		} else {
			benchCode.Push(0)
			benchCode.Op(ops.DUP1)
			benchCode.Op(ops.DUP1)
			benchCode.Op(ops.DUP1)
			benchCode.Push(4)
			benchCode.Op(ops.GASLIMIT)
			benchCode.Op(ops.STATICCALL)
		}
		benchCode.Op(ops.POP)
	}
	benchCode.Op(ops.POP)
	// stack: loop counter, precompile address, output size, input size
	benchCode.Op(ops.DUP4)
	benchCode.Op(ops.DUP4)
	benchCode.Op(ops.SWAP1)
	benchCode.Op(ops.RETURN)
	return benchCode
}
func randomG1Point(input io.Reader) *bls12381.G1Affine {
	// sample a random scalar
	s := randomScalar(input, fp.Modulus())

	// compute a random point
	pt := new(bls12381.G1Affine)
	_, _, g1Gen, _ := bls12381.Generators()
	pt.ScalarMultiplication(&g1Gen, s)

	return pt
}

func randomG2Point(input io.Reader) *bls12381.G2Affine {
	// sample a random scalar
	s := randomScalar(input, fp.Modulus())

	// compute a random point
	pt := new(bls12381.G2Affine)
	_, _, _, g2Gen := bls12381.Generators()
	pt.ScalarMultiplication(&g2Gen, s)
	return pt
}

func randomScalar(r io.Reader) (k *big.Int) {
	k, _ = rand.Int(r, math.MaxBig256)
	return k
}

func marshalScalar(k *big.Int) (res []byte) {
	kBytes := k.Bytes()
	res = make([]byte, 256)
	copy(res[256-len(kBytes):], kBytes)
	return res
}

/*
func randomFr(r io.Reader) *fr.Element {
	scalar := randomScalar(r, fr.Modulus())
	res := new(fr.Element)
	res.SetBytes(scalar.Bytes())
	return res
}
*/

func marshalFr(elem fr.Element) []byte {
	return elem.Marshal()
}

func marshalFp(elem fp.Element) []byte {
	res := make([]byte, 64)
	copy(res[16:], elem.Marshal())
	return res
}

func marshalG1Point(pt *bls12381.G1Affine) []byte {
	resX := marshalFp(pt.X)
	resY := marshalFp(pt.Y)

	return append(resX, resY...)
}

func marshalG2Point(pt *bls12381.G2Affine) []byte {
	resX_0 := marshalFp(pt.X.A0)
	resX_1 := marshalFp(pt.X.A1)
	resY_0 := marshalFp(pt.Y.A0)
	resY_1 := marshalFp(pt.Y.A1)
	res := append(resX_0, resX_1...)
	res = append(res, resY_0...)
	res = append(res, resY_1...)
	return res
}

func genG1MSMInputs(r io.Reader, inputCount int) (res []byte) {
	for i := 0; i < inputCount; i++ {
		res = append(res, randomG1Point(r).Marshal()...)
		res = append(res, marshalScalar(randomScalar(r))...)
	}
	return res
}

func genG2MSMInputs(r io.Reader, inputCount int) (res []byte) {
	for i := 0; i < inputCount; i++ {
		res = append(res, randomG2Point(r).Marshal()...)
		res = append(res, marshalScalar(randomScalar(r))...)
	}
	return res
}

func generateBenchInputs(precompile common.Address, inputCount int) []byte {
	var res []byte
	switch precompile {
	case common.BytesToAddress([]byte{0x0b}):
		// g1 add
		_, _, g1Gen, _ := bls12381.Generators()
		pt1 := g1Gen.ScalarMultiplication(&g1Gen, big.NewInt(2))
		pt2 := g1Gen
		res = append(res, marshalG1Point(pt1)...)
		res = append(res, marshalG1Point(&pt2)...)
	case common.BytesToAddress([]byte{0x0c}): // g1 mul
		highArityScalar := new(big.Int)
		highArityScalar.SetString("0x...", 16)
	case common.BytesToAddress([]byte{0x0d}): // g1 msm
		res = append(res, genG1MSMInputs(r, inputCount)...)
	case common.BytesToAddress([]byte{0x0e}): // g2 add
	}
}

func generateAlloc() core.GenesisAlloc {
	var alloc core.GenesisAlloc
	benchContractAddr := common.HexToAddress("0xdeadbeef")
}

// convertToStateTest is a utility to turn stuff into sharable state tests.
func convertToStateTest(name, fork string, alloc core.GenesisAlloc, gasLimit uint64,
	target common.Address) error {

	mkr := fuzzing.BasicStateTest(fork)
	// convert the genesisAlloc
	var fuzzGenesisAlloc = make(fuzzing.GenesisAlloc)
	for k, v := range alloc {
		fuzzAcc := fuzzing.GenesisAccount{
			Code:       v.Code,
			Storage:    v.Storage,
			Balance:    v.Balance,
			Nonce:      v.Nonce,
			PrivateKey: v.PrivateKey,
		}
		if fuzzAcc.Balance == nil {
			fuzzAcc.Balance = new(big.Int)
		}
		if fuzzAcc.Storage == nil {
			fuzzAcc.Storage = make(map[common.Hash]common.Hash)
		}
		fuzzGenesisAlloc[k] = fuzzAcc
	}
	// Also add the sender
	var sender = common.HexToAddress("a94f5374fce5edbc8e2a8697c15331677e6ebf0b")
	if _, ok := fuzzGenesisAlloc[sender]; !ok {
		fuzzGenesisAlloc[sender] = fuzzing.GenesisAccount{
			Balance: big.NewInt(1000000000000000000), // 1 eth
			Nonce:   0,
			Storage: make(map[common.Hash]common.Hash),
		}
	}

	tx := &fuzzing.StTransaction{
		GasLimit:   []uint64{gasLimit},
		Nonce:      0,
		Value:      []string{"0x0"},
		Data:       []string{""},
		GasPrice:   big.NewInt(0x10),
		PrivateKey: hexutil.MustDecode("0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8"),
		To:         target.Hex(),
	}
	mkr.SetTx(tx)
	mkr.SetPre(&fuzzGenesisAlloc)
	if err := mkr.Fill(nil); err != nil {
		return err
	}
	gst := mkr.ToGeneralStateTest(name)
	dat, _ := json.MarshalIndent(gst, "", " ")
	fname := fmt.Sprintf("%v.json", name)
	if err := os.WriteFile(fname, dat, 0777); err != nil {
		return err
	}
	fmt.Printf("Wrote file %v\n", fname)
	return nil
}
