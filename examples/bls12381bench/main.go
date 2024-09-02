package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core"
	"github.com/holiman/goevmlab/fuzzing"
	"github.com/holiman/goevmlab/ops"
	"github.com/holiman/goevmlab/program"
	"github.com/holiman/uint256"
	"github.com/urfave/cli/v2"
	"io"
	"math/big"
	"os"
	"path/filepath"
)

func initApp() *cli.App {
	app := cli.NewApp()
	app.Name = filepath.Base(os.Args[0])
	app.Authors = []*cli.Author{{Name: "Jared Wasinger"}}
	app.Usage = "Generator for bls precompile benchmarks"
	return app
}

var (
	app            = initApp()
	precompileFlag = &cli.StringFlag{
		Name:  "precompile",
		Value: "",
		Usage: "which bls precompile to benchmark",
	}
	inputCountFlag = &cli.IntFlag{
		Name:  "input-count",
		Value: 1,
		Usage: "number of inputs to use (for pairing and msm precompiles)",
	}
	evaluateCommand = &cli.Command{
		Action:      evaluate,
		Name:        "evaluate",
		Usage:       "evaluate the test using the built-in go-ethereum base",
		Description: `Evaluate the test using the built-in go-ethereum library.`,
	}
)

func init() {
	app.Flags = []cli.Flag{
		precompileFlag,
		inputCountFlag,
	}
	app.Commands = []*cli.Command{
		evaluateCommand,
	}
}

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func precompileNameToAddress(name string) common.Address {
	switch name {
	case "g1add":
		return common.BytesToAddress([]byte{0x0b})
	case "g1mul":
		return common.BytesToAddress([]byte{0x0c})
	case "g1msm":
		return common.BytesToAddress([]byte{0x0d})
	case "g2add":
		return common.BytesToAddress([]byte{0x0e})
	case "g2mul":
		return common.BytesToAddress([]byte{0x0f})
	case "g2msm":
		return common.BytesToAddress([]byte{0x10})
	case "pairing":
		return common.BytesToAddress([]byte{0x11})
	case "mapfp":
		return common.BytesToAddress([]byte{0x12})
	case "mapfp2":
		return common.BytesToAddress([]byte{0x13})
	default:
		panic(fmt.Sprintf("invalid precompile selection", name))
	}
}

func evaluate(ctx *cli.Context) error {
	var (
		precompileName = ctx.String(precompileFlag.Name)
		precompile     = precompileNameToAddress(precompileName)
		inputCount     = ctx.Int(inputCountFlag.Name)
	)
	alloc := generateAlloc()
	input := generateBenchInputs(rand.Reader, precompile, inputCount)
	if err := convertToStateTest(fmt.Sprintf("bench-%s", precompileName), "Prague", alloc, 1_000_000_000, benchContractAddr, input); err != nil {
		return err
	}
	return nil
}

func generateBenchCode(iterCount int, isNoop bool) *program.Program {
	benchCode := program.NewProgram()
	benchCode.CalldataLoad(0)

	benchCode.Op(ops.DUP1)
	benchCode.Push(uint256.MustFromHex("0xffffffffffffffffffffffffffffffff00000000000000000000000000000000"))
	benchCode.Op(ops.AND)
	benchCode.Push(0x80)
	benchCode.Op(ops.SHR)
	benchCode.Op(ops.SWAP1)
	// stack: calldata[0], input_size

	benchCode.Push(uint256.MustFromHex("0xffffffffffffffffffffffffffffffff"))
	benchCode.Op(ops.AND)
	//stack: output_size, input_size

	// mem[0:input_size+output_size] <- calldatacopy(calldata[32:32+input_size+output_size])
	benchCode.Op(ops.DUP1)
	benchCode.Op(ops.DUP3)
	benchCode.Op(ops.ADD)
	benchCode.Push(0x34)
	benchCode.Push(0)
	benchCode.Op(ops.CALLDATACOPY)

	benchCode.Push(0x20)
	benchCode.Op(ops.CALLDATALOAD)
	benchCode.Push(0x60)
	benchCode.Op(ops.SHR)
	//stack: precompile_address, output_size, input_size

	benchCode.Push(uint256.MustFromHex("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00"))
	benchCode.Op(ops.DUP4)

	for i := 0; i < iterCount; i++ {
		if !isNoop {
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
	s := randomScalar(input)

	// compute a random point
	pt := new(bls12381.G1Affine)
	_, _, g1Gen, _ := bls12381.Generators()
	pt.ScalarMultiplication(&g1Gen, s)

	return pt
}

func randomG2Point(input io.Reader) *bls12381.G2Affine {
	// sample a random scalar
	s := randomScalar(input)

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

// marshal 32 bit scalar
func marshalScalar(k *big.Int) (res []byte) {
	kBytes := k.Bytes()
	res = make([]byte, 32)
	copy(res[32-len(kBytes):], kBytes)
	return res
}

func randomFp(r io.Reader) fp.Element {
	randFp, _ := rand.Int(r, fp.Modulus())
	scalar := new(fp.Element)
	scalar.SetBytes(randFp.Bytes())
	return *scalar
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
		res = append(res, marshalG1Point(randomG1Point(r))...)
		res = append(res, marshalScalar(randomScalar(r))...)
	}
	return res
}

func genG2MSMInputs(r io.Reader, inputCount int) (res []byte) {
	for i := 0; i < inputCount; i++ {
		res = append(res, marshalG2Point(randomG2Point(r))...)
		res = append(res, marshalScalar(randomScalar(r))...)
	}
	return res
}

func genPairingInputs(r io.Reader, inputCount int) (res []byte) {
	for i := 0; i < inputCount; i++ {
		res = append(res, marshalG1Point(randomG1Point(r))...)
		res = append(res, marshalG2Point(randomG2Point(r))...)
	}
	return res
}

func encodeU128(val uint64) []byte {
	res := make([]byte, 16)
	binary.BigEndian.PutUint64(res[8:16], val)
	return res
}

func generateBenchInputs(r io.Reader, precompile common.Address, inputCount int) []byte {
	var res []byte
	var precompileInput []byte

	switch precompile {
	case common.BytesToAddress([]byte{0x0b}):
		// g1 add
		res = append(res, encodeU128(2*128)...) // input size
		res = append(res, encodeU128(128)...)   // output size
		_, _, g1Gen, _ := bls12381.Generators()
		pt1 := g1Gen.ScalarMultiplication(&g1Gen, big.NewInt(2))
		pt2 := g1Gen
		precompileInput = append(precompileInput, marshalG1Point(pt1)...)
		precompileInput = append(precompileInput, marshalG1Point(&pt2)...)
	case common.BytesToAddress([]byte{0x0c}): // g1 mul
		res = append(res, encodeU128(128+32)...) // input size
		res = append(res, encodeU128(128)...)    // output size
		_, _, g1Gen, _ := bls12381.Generators()
		highArityScalar := new(big.Int)
		highArityScalar.SetString("50597600879605352240557443896859274688352069811191692694697732254669473040618", 10)
		precompileInput = append(precompileInput, marshalG1Point(&g1Gen)...)
		precompileInput = append(precompileInput, marshalScalar(highArityScalar)...)
	case common.BytesToAddress([]byte{0x0d}): // g1 msm
		res = append(res, encodeU128(uint64(inputCount)*(128+32))...) // input size
		res = append(res, encodeU128(128)...)                         // output size
		precompileInput = append(precompileInput, genG1MSMInputs(r, inputCount)...)
	case common.BytesToAddress([]byte{0x0e}): // g2 add
		res = append(res, encodeU128(2*256)...) // input size
		res = append(res, encodeU128(256)...)   // output size
		_, _, _, g2Gen := bls12381.Generators()
		pt1 := g2Gen.ScalarMultiplication(&g2Gen, big.NewInt(2))
		pt2 := g2Gen
		precompileInput = append(precompileInput, marshalG2Point(pt1)...)
		precompileInput = append(precompileInput, marshalG2Point(&pt2)...)
	case common.BytesToAddress([]byte{0x0f}): // g2 mul
		res = append(res, encodeU128(256+32)...) // input size
		res = append(res, encodeU128(256)...)    // output size
		_, _, _, g2Gen := bls12381.Generators()
		highArityScalar := new(big.Int)
		highArityScalar.SetString("50597600879605352240557443896859274688352069811191692694697732254669473040618", 10)
		precompileInput = append(precompileInput, marshalG2Point(&g2Gen)...)
		precompileInput = append(precompileInput, marshalScalar(highArityScalar)...)
	case common.BytesToAddress([]byte{0x10}): // g2 msm
		res = append(res, encodeU128(uint64(inputCount)*(256+32))...) // input size
		res = append(res, encodeU128(128)...)                         // output size
		precompileInput = append(precompileInput, genG2MSMInputs(r, inputCount)...)
	case common.BytesToAddress([]byte{0x11}): // pairing check
		res = append(res, encodeU128(uint64(inputCount)*(256+128))...) // input size
		res = append(res, encodeU128(32)...)                           // output size
		precompileInput = append(precompileInput, genPairingInputs(r, inputCount)...)
	case common.BytesToAddress([]byte{0x12}): // MapFp
		res = append(res, encodeU128(uint64(inputCount)*32)...) // input size
		res = append(res, encodeU128(128)...)                   // output size
		precompileInput = append(precompileInput, marshalFp(randomFp(r))...)
	case common.BytesToAddress([]byte{0x13}): // MapFp2
		res = append(res, encodeU128(uint64(inputCount)*(32*2))...) // input size
		res = append(res, encodeU128(256)...)                       // output size
		precompileInput = append(precompileInput, marshalFp(randomFp(r))...)
		precompileInput = append(precompileInput, marshalFp(randomFp(r))...)
	}
	res = append(res, precompile.Bytes()...)
	res = append(res, precompileInput...)
	return res
}

var benchContractAddr = common.HexToAddress("0xdeadbeef")

func generateAlloc() core.GenesisAlloc {
	var alloc core.GenesisAlloc
	benchCode := generateBenchCode(2850, false).Bytecode()
	alloc = make(core.GenesisAlloc)
	alloc[benchContractAddr] = core.GenesisAccount{
		Code: benchCode,
	}
	return alloc
}

// convertToStateTest is a utility to turn stuff into sharable state tests.
func convertToStateTest(name, fork string, alloc core.GenesisAlloc, gasLimit uint64,
	target common.Address, txData []byte) error {

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
		maxBalance := new(big.Int)
		maxBalance.SetUint64(math.MaxUint64)
		fuzzGenesisAlloc[sender] = fuzzing.GenesisAccount{
			Balance: maxBalance,
			Nonce:   0,
			Storage: make(map[common.Hash]common.Hash),
		}
	}

	tx := &fuzzing.StTransaction{
		GasLimit:   []uint64{gasLimit},
		Nonce:      0,
		Value:      []string{"0x0"},
		Data:       []string{fmt.Sprintf("0x%x", txData)},
		GasPrice:   big.NewInt(0x10),
		Sender:     sender,
		PrivateKey: hexutil.MustDecode("0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8"),
		To:         target.Hex(),
	}
	mkr.SetTx(tx)
	mkr.SetPre(&fuzzGenesisAlloc)
	fmt.Println("before fill")
	if err := mkr.Fill(os.Stdout); err != nil {
		return err
	}
	fmt.Println("after fill")
	gst := mkr.ToGeneralStateTest(name)
	dat, _ := json.MarshalIndent(gst, "", " ")
	fname := fmt.Sprintf("%v.json", name)
	if err := os.WriteFile(fname, dat, 0777); err != nil {
		return err
	}
	fmt.Printf("Wrote file %v\n", fname)
	return nil
}
