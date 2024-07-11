## Go MultiAdaptiveClient

Official Golang execution layer implementation of the MultiAdaptiveClient.

Automated builds are available for stable releases and the unstable master branch. Binary
archives are published at https://github.com/MultiAdaptive/MultiAdaptiveClient.

## Building the source

Building `geth` requires both a Go (version 1.21.3 or later) and a C compiler. You can install
them using your favourite package manager. Once the dependencies are installed, run

```shell
make geth
```

## Executables

The MultiAdaptiveClient project comes with several wrappers/executables found in the `cmd`
directory.

|  Command   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| :--------: | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`geth`** | Our main MultiAdaptive CLI client. It is the entry point into the MultiAdaptive network (main-, test-), capable of running as a broadcast node (default), storag node (retaining all historical specisic DA). It can be used by other processes as a gateway into the Ethereum network via JSON RPC endpoints exposed on top of HTTP, WebSocket and/or IPC transports. `geth --help` and the [CLI page](https://geth.ethereum.org/docs/fundamentals/command-line-options) for command line options. |                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `bootnode` | Stripped down version of our MultiAdaptive client implementation that only takes part in the network node discovery protocol, but does not run any of the higher level application protocols. It can be used as a lightweight bootstrap node to aid in finding peers in private networks.                                                                                                                                                                                                                                               |


## Running `geth`

Going through all the possible command line flags is out of scope here (please consult our
[CLI Wiki page](https://geth.ethereum.org/docs/fundamentals/command-line-options)),
but we've enumerated a few common parameter combos to get you up to speed quickly
on how you can run your own `geth` instance.

### Hardware Requirements

Minimum:

* CPU with 2+ cores
* 4GB RAM
* 100GB free storage space to sync the Mainnet
* 8 MBit/sec download Internet service

Recommended:

* Fast CPU with 4+ cores
* 16GB+ RAM
* High-performance SSD with at least 1TB of free space
* 25+ MBit/sec download Internet service


### Programmatically interfacing `geth` nodes

As a developer, sooner rather than later you'll want to start interacting with `geth` and the
Ethereum network via your own programs and not manually through the console. To aid
this, `geth` has built-in support for a JSON-RPC based APIs ([standard APIs](https://ethereum.github.io/execution-apis/api-documentation/)
and [`geth` specific APIs](https://geth.ethereum.org/docs/interacting-with-geth/rpc)).
These can be exposed via HTTP, WebSockets and IPC (UNIX sockets on UNIX based
platforms, and named pipes on Windows).

The IPC interface is enabled by default and exposes all the APIs supported by `geth`,
whereas the HTTP and WS interfaces need to manually be enabled and only expose a
subset of APIs due to security reasons. These can be turned on/off and configured as
you'd expect.

HTTP based JSON-RPC API options:

  * `--http` Enable the HTTP-RPC server
  * `--http.addr` HTTP-RPC server listening interface (default: `localhost`)
  * `--http.port` HTTP-RPC server listening port (default: `8545`)
  * `--http.api` API's offered over the HTTP-RPC interface (default: `eth,net,web3`)

  * `--ws` Enable the WS-RPC server
  * `--ws.addr` WS-RPC server listening interface (default: `localhost`)
  * `--ws.port` WS-RPC server listening port (default: `8546`)
  * `--ws.api` API's offered over the WS-RPC interface (default: `eth,net,web3`)
  * `--ws.origins` Origins from which to accept WebSocket requests

You'll need to use your own programming environments' capabilities (libraries, tools, etc) to
connect via HTTP, WS or IPC to a `geth` node configured with the above flags and you'll
need to speak [JSON-RPC](https://www.jsonrpc.org/specification) on all transports. You
can reuse the same connection for multiple requests!

**Note: Please understand the security implications of opening up an HTTP/WS based
transport before doing so! Hackers on the internet are actively trying to subvert
Ethereum nodes with exposed APIs! Further, all browser tabs can access locally
running web servers, so malicious web pages could try to subvert locally available
APIs!**


#### Defining the private genesis state

First, you'll need to create the genesis state of your networks, which all nodes need to be
aware of and agree upon. This consists of a small JSON file (e.g. call it `genesis.json`):

```json
{
  "config": {
    "chainId": 11155111,
    "homesteadBlock": 0,
    "eip150Block": 0,
    "eip155Block": 0,
    "eip158Block": 0,
    "byzantiumBlock": 0,
    "constantinopleBlock": 0,
    "petersburgBlock": 0,
    "istanbulBlock": 0,
    "muirGlacierBlock": 0,
    "berlinBlock": 0,
    "londonBlock": 0,
    "arrowGlacierBlock": 0,
    "grayGlacierBlock": 0,
    "mergeNetsplitBlock": 0,
    "bedrockBlock": 0,
    "regolithTime": 0,
    "terminalTotalDifficulty": 0,
    "terminalTotalDifficultyPassed": true,
    "l1Conf": {
        "genesisBlockNumber": 6287400,
        "addressManager": "0x3CFAb5036e6Eefa7FE44D9f52f6AA36cC4C67983",
        "challengeContract": "0xBde58e53660eD722F2e0F13499ad8B784735559C",
        "challengeContractProxy": "0xDE079f7DB4610b213e6895a19F2D35002D2eFfAf",
        "commitmentManager": "0x725CdbD3aF6b93C61959e5555a20e660cB49219F",
        "commitmentManagerProxy": "0xa8ED91Eb2B65A681A742011798d7FB31C50FA724",
        "nodeManager": "0xEd0a112172faFaEFa0e7faCA1A486cEdaCE828bD",
        "nodeManagerProxy": "0x97bE3172AEA87b60224e8d604aC4bAbe55F067EC",
        "proxyAdmin": "0xc4a2c32fdEb995115FA2564Bab1E1322bB7003Fe",
        "safeProxyFactory": "0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2",
        "safeSingleton": "0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552",
        "storageManager": "0x794161e6b0e14FbDD400032b6A670bF18cBC9f83",
        "storageManagerProxy": "0x664250Fb3b1cd58f07683D957A34daf8A06130fe",
        "systemOwnerSafe": "0xB37CB13df96f98F8ac040fAa3Eb382d84f3d9e23" 
   }
  },
  "nonce": "0x0",
  "timestamp": "0x659b6e60",
  "extraData": "0x424544524f434b",
  "gasLimit": "0x1c9c380",
  "difficulty": "0x0",
  "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "coinbase": "0x4200000000000000000000000000000000000011",
  "alloc": {},
  "number": "0x0",
  "gasUsed": "0x0",
  "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "baseFeePerGas": "0x3b9aca00",
  "excessBlobGas": null,
  "blobGasUsed": null
}
```
With the genesis state defined in the above JSON file, you'll need to initialize **every**
`geth` node with it prior to starting it up to ensure all blockchain parameters are correctly
set:

```shell
$ geth init path/to/genesis.json
```

#### Starting up your member nodes

With the bootnode operational and externally reachable (you can try
`telnet <ip> <port>` to ensure it's indeed reachable), start every subsequent `geth`
node pointed to the bootnode for peer discovery via the `--bootnodes` flag. It will
probably also be desirable to keep the data directory of your private network separated, so
do also specify a custom `--datadir` flag.

```shell
$ geth --datadir=path/to/custom/data/folder --bootnodes=<bootnode-enode-url-from-above>
```



