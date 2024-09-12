package main

import (
	"fmt"
	"github.com/ethereum/go-ethereum/log"
	"github.com/holiman/goevmlab/common"
	"github.com/urfave/cli/v2"
	"os"
	"path/filepath"
)

func initApp() *cli.App {
	app := cli.NewApp()
	app.Name = filepath.Base(os.Args[0])
	app.Authors = []*cli.Author{{Name: "Jared Wasinger"}}
	app.Usage = "State test benchmarker"
	app.Flags = append(app.Flags, common.VmFlags...)
	app.Action = runBench
	return app
}

var app = initApp()

func runBench(c *cli.Context) error {
	testPath := c.Args().First()
	res, gasUsed := common.BenchSingleTest(testPath, c)
	gasPerOp := gasUsed / 2850
	for vmName, execTime := range res {
		fmt.Println(execTime)
		execTimePerOp := uint64(execTime) / 2850
		throughput := (float64(gasPerOp) / float64(execTimePerOp)) * 1e9
		/*
			fmt.Println(gasPerOp)
			fmt.Println(execTimePerOp)
		*/
		fmt.Println(gasUsed)
		fmt.Println(execTime)
		fmt.Printf("%s - %f gas per second\n", vmName, throughput)
	}
	return nil
}

func main() {
	log.SetDefault(log.NewLogger(log.NewTerminalHandlerWithLevel(os.Stderr, log.LevelDebug, true)))
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
