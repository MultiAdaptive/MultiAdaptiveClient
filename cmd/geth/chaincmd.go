// Copyright 2015 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"encoding/json"
	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/internal/flags"
	"github.com/ethereum/go-ethereum/log"
	"github.com/urfave/cli/v2"
	"os"
	"strconv"
)

var (
	initCommand = &cli.Command{
		Action:    initGenesis,
		Name:      "init",
		Usage:     "Bootstrap and initialize a new genesis block",
		ArgsUsage: "<genesisPath>",
		Flags: flags.Merge([]cli.Flag{
			utils.CachePreimagesFlag,
		}, utils.DatabaseFlags),
		Description: `
The init command initializes a new genesis block and definition for the network.
This is a destructive action and changes the network in which you will be
participating.

It expects the genesis file as argument.`,
	}
	dumpGenesisCommand = &cli.Command{
		Action:    dumpGenesis,
		Name:      "dumpgenesis",
		Usage:     "Dumps genesis block JSON configuration to stdout",
		ArgsUsage: "",
		Flags:     append([]cli.Flag{utils.DataDirFlag}, utils.NetworkFlags...),
		Description: `
The dumpgenesis command prints the genesis configuration of the network preset
if one is set.  Otherwise it prints the genesis from the datadir.`,
	}
)

// initGenesis will initialise the given JSON format genesis file and writes it as
// the zero'd block (i.e. genesis) or will fail hard if it can't succeed.
func initGenesis(ctx *cli.Context) error {
	if ctx.Args().Len() != 1 {
		utils.Fatalf("need genesis.json file as the only argument")
	}
	genesisPath := ctx.Args().First()
	if len(genesisPath) == 0 {
		utils.Fatalf("invalid path to genesis file")
	}
	file, err := os.Open(genesisPath)
	if err != nil {
		utils.Fatalf("Failed to read genesis file: %v", err)
	}
	defer file.Close()

	genesis := new(core.Genesis)
	if err := json.NewDecoder(file).Decode(genesis); err != nil {
		utils.Fatalf("invalid genesis file: %v", err)
	}
	// Open and initialise both full and light databases
	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	for _, name := range []string{"chaindata", "lightchaindata"} {
		chaindb, err := stack.OpenDatabaseWithFreezer(name, 0, 0, ctx.String(utils.AncientFlag.Name), "", false)
		if err != nil {
			utils.Fatalf("Failed to open database: %v", err)
		}
		defer chaindb.Close()

		triedb := utils.MakeTrieDatabase(ctx, chaindb, ctx.Bool(utils.CachePreimagesFlag.Name), false)
		defer triedb.Close()

		//TODO SHOULD FIX THIS
		//_, hash, err := core.SetupGenesisBlock(chaindb, triedb, genesis)
		if err != nil {
			utils.Fatalf("Failed to write genesis block: %v", err)
		}
		log.Info("Successfully wrote genesis state", "database", name)
	}
	return nil
}

func dumpGenesis(ctx *cli.Context) error {
	// if there is a testnet preset enabled, dump that
	if utils.IsNetworkPreset(ctx) {
		genesis := utils.MakeGenesis(ctx)
		if err := json.NewEncoder(os.Stdout).Encode(genesis); err != nil {
			utils.Fatalf("could not encode genesis: %s", err)
		}
		return nil
	}
	// dump whatever already exists in the datadir
	stack, _ := makeConfigNode(ctx)
	for _, name := range []string{"chaindata", "lightchaindata"} {
		db, err := stack.OpenDatabase(name, 0, 0, "", true)
		if err != nil {
			if !os.IsNotExist(err) {
				return err
			}
			continue
		}
		//TODO SHOULD FIX THIS
		//genesis, err := core.ReadGenesis(db)
		if err != nil {
			utils.Fatalf("failed to read genesis: %s", err)
		}
		db.Close()
		//
		//if err := json.NewEncoder(os.Stdout).Encode(*nil); err != nil {
		//	utils.Fatalf("could not encode stored genesis: %s", err)
		//}
		return nil
	}
	if ctx.IsSet(utils.DataDirFlag.Name) {
		utils.Fatalf("no existing datadir at %s", stack.Config().DataDir)
	}
	utils.Fatalf("no network preset provided, no existing genesis in the default datadir")
	return nil
}

// hashish returns true for strings that look like hashes.
func hashish(x string) bool {
	_, err := strconv.Atoi(x)
	return err != nil
}
