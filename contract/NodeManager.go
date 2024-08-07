// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package contract

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// NodeManagerNodeInfo is an auto generated low-level Go binding around an user-defined struct.
type NodeManagerNodeInfo struct {
	Url             string
	Name            string
	StakedTokens    *big.Int
	Location        string
	MaxStorageSpace *big.Int
	Addr            common.Address
}

// NodeManagerMetaData contains all meta data concerning the NodeManager contract.
var NodeManagerMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"constructor\",\"inputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"broadcastNodeList\",\"inputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"broadcastingNodes\",\"inputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"url\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"name\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"stakedTokens\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"location\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"maxStorageSpace\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"addr\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getBroadcastingNodes\",\"inputs\":[],\"outputs\":[{\"name\":\"nodes\",\"type\":\"tuple[]\",\"internalType\":\"structNodeManager.NodeInfo[]\",\"components\":[{\"name\":\"url\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"name\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"stakedTokens\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"location\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"maxStorageSpace\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"addr\",\"type\":\"address\",\"internalType\":\"address\"}]}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getStorageNodes\",\"inputs\":[],\"outputs\":[{\"name\":\"nodes\",\"type\":\"tuple[]\",\"internalType\":\"structNodeManager.NodeInfo[]\",\"components\":[{\"name\":\"url\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"name\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"stakedTokens\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"location\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"maxStorageSpace\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"addr\",\"type\":\"address\",\"internalType\":\"address\"}]}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"initialize\",\"inputs\":[],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"isNodeBroadcast\",\"inputs\":[{\"name\":\"addr\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"isNodeStorage\",\"inputs\":[{\"name\":\"addr\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"registerBroadcastNode\",\"inputs\":[{\"name\":\"info\",\"type\":\"tuple\",\"internalType\":\"structNodeManager.NodeInfo\",\"components\":[{\"name\":\"url\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"name\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"stakedTokens\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"location\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"maxStorageSpace\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"addr\",\"type\":\"address\",\"internalType\":\"address\"}]}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"registerStorageNode\",\"inputs\":[{\"name\":\"info\",\"type\":\"tuple\",\"internalType\":\"structNodeManager.NodeInfo\",\"components\":[{\"name\":\"url\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"name\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"stakedTokens\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"location\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"maxStorageSpace\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"addr\",\"type\":\"address\",\"internalType\":\"address\"}]}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"storageNodeList\",\"inputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"storageNodes\",\"inputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"url\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"name\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"stakedTokens\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"location\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"maxStorageSpace\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"addr\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"version\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"view\"},{\"type\":\"event\",\"name\":\"BroadcastNode\",\"inputs\":[{\"name\":\"add\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"url\",\"type\":\"string\",\"indexed\":false,\"internalType\":\"string\"},{\"name\":\"name\",\"type\":\"string\",\"indexed\":false,\"internalType\":\"string\"},{\"name\":\"stakedTokens\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"Initialized\",\"inputs\":[{\"name\":\"version\",\"type\":\"uint8\",\"indexed\":false,\"internalType\":\"uint8\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"StorageNode\",\"inputs\":[{\"name\":\"add\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"url\",\"type\":\"string\",\"indexed\":false,\"internalType\":\"string\"},{\"name\":\"name\",\"type\":\"string\",\"indexed\":false,\"internalType\":\"string\"},{\"name\":\"stakedTokens\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"}],\"anonymous\":false}]",
}

// NodeManagerABI is the input ABI used to generate the binding from.
// Deprecated: Use NodeManagerMetaData.ABI instead.
var NodeManagerABI = NodeManagerMetaData.ABI

// NodeManager is an auto generated Go binding around an Ethereum contract.
type NodeManager struct {
	NodeManagerCaller     // Read-only binding to the contract
	NodeManagerTransactor // Write-only binding to the contract
	NodeManagerFilterer   // Log filterer for contract events
}

// NodeManagerCaller is an auto generated read-only Go binding around an Ethereum contract.
type NodeManagerCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// NodeManagerTransactor is an auto generated write-only Go binding around an Ethereum contract.
type NodeManagerTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// NodeManagerFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type NodeManagerFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// NodeManagerSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type NodeManagerSession struct {
	Contract     *NodeManager      // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// NodeManagerCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type NodeManagerCallerSession struct {
	Contract *NodeManagerCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts      // Call options to use throughout this session
}

// NodeManagerTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type NodeManagerTransactorSession struct {
	Contract     *NodeManagerTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts      // Transaction auth options to use throughout this session
}

// NodeManagerRaw is an auto generated low-level Go binding around an Ethereum contract.
type NodeManagerRaw struct {
	Contract *NodeManager // Generic contract binding to access the raw methods on
}

// NodeManagerCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type NodeManagerCallerRaw struct {
	Contract *NodeManagerCaller // Generic read-only contract binding to access the raw methods on
}

// NodeManagerTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type NodeManagerTransactorRaw struct {
	Contract *NodeManagerTransactor // Generic write-only contract binding to access the raw methods on
}

// NewNodeManager creates a new instance of NodeManager, bound to a specific deployed contract.
func NewNodeManager(address common.Address, backend bind.ContractBackend) (*NodeManager, error) {
	contract, err := bindNodeManager(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &NodeManager{NodeManagerCaller: NodeManagerCaller{contract: contract}, NodeManagerTransactor: NodeManagerTransactor{contract: contract}, NodeManagerFilterer: NodeManagerFilterer{contract: contract}}, nil
}

// NewNodeManagerCaller creates a new read-only instance of NodeManager, bound to a specific deployed contract.
func NewNodeManagerCaller(address common.Address, caller bind.ContractCaller) (*NodeManagerCaller, error) {
	contract, err := bindNodeManager(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &NodeManagerCaller{contract: contract}, nil
}

// NewNodeManagerTransactor creates a new write-only instance of NodeManager, bound to a specific deployed contract.
func NewNodeManagerTransactor(address common.Address, transactor bind.ContractTransactor) (*NodeManagerTransactor, error) {
	contract, err := bindNodeManager(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &NodeManagerTransactor{contract: contract}, nil
}

// NewNodeManagerFilterer creates a new log filterer instance of NodeManager, bound to a specific deployed contract.
func NewNodeManagerFilterer(address common.Address, filterer bind.ContractFilterer) (*NodeManagerFilterer, error) {
	contract, err := bindNodeManager(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &NodeManagerFilterer{contract: contract}, nil
}

// bindNodeManager binds a generic wrapper to an already deployed contract.
func bindNodeManager(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := NodeManagerMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_NodeManager *NodeManagerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _NodeManager.Contract.NodeManagerCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_NodeManager *NodeManagerRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _NodeManager.Contract.NodeManagerTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_NodeManager *NodeManagerRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _NodeManager.Contract.NodeManagerTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_NodeManager *NodeManagerCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _NodeManager.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_NodeManager *NodeManagerTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _NodeManager.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_NodeManager *NodeManagerTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _NodeManager.Contract.contract.Transact(opts, method, params...)
}

// BroadcastNodeList is a free data retrieval call binding the contract method 0x56f7be58.
//
// Solidity: function broadcastNodeList(uint256 ) view returns(address)
func (_NodeManager *NodeManagerCaller) BroadcastNodeList(opts *bind.CallOpts, arg0 *big.Int) (common.Address, error) {
	var out []interface{}
	err := _NodeManager.contract.Call(opts, &out, "broadcastNodeList", arg0)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// BroadcastNodeList is a free data retrieval call binding the contract method 0x56f7be58.
//
// Solidity: function broadcastNodeList(uint256 ) view returns(address)
func (_NodeManager *NodeManagerSession) BroadcastNodeList(arg0 *big.Int) (common.Address, error) {
	return _NodeManager.Contract.BroadcastNodeList(&_NodeManager.CallOpts, arg0)
}

// BroadcastNodeList is a free data retrieval call binding the contract method 0x56f7be58.
//
// Solidity: function broadcastNodeList(uint256 ) view returns(address)
func (_NodeManager *NodeManagerCallerSession) BroadcastNodeList(arg0 *big.Int) (common.Address, error) {
	return _NodeManager.Contract.BroadcastNodeList(&_NodeManager.CallOpts, arg0)
}

// BroadcastingNodes is a free data retrieval call binding the contract method 0xcac5800a.
//
// Solidity: function broadcastingNodes(address ) view returns(string url, string name, uint256 stakedTokens, string location, uint256 maxStorageSpace, address addr)
func (_NodeManager *NodeManagerCaller) BroadcastingNodes(opts *bind.CallOpts, arg0 common.Address) (struct {
	Url             string
	Name            string
	StakedTokens    *big.Int
	Location        string
	MaxStorageSpace *big.Int
	Addr            common.Address
}, error) {
	var out []interface{}
	err := _NodeManager.contract.Call(opts, &out, "broadcastingNodes", arg0)

	outstruct := new(struct {
		Url             string
		Name            string
		StakedTokens    *big.Int
		Location        string
		MaxStorageSpace *big.Int
		Addr            common.Address
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.Url = *abi.ConvertType(out[0], new(string)).(*string)
	outstruct.Name = *abi.ConvertType(out[1], new(string)).(*string)
	outstruct.StakedTokens = *abi.ConvertType(out[2], new(*big.Int)).(**big.Int)
	outstruct.Location = *abi.ConvertType(out[3], new(string)).(*string)
	outstruct.MaxStorageSpace = *abi.ConvertType(out[4], new(*big.Int)).(**big.Int)
	outstruct.Addr = *abi.ConvertType(out[5], new(common.Address)).(*common.Address)

	return *outstruct, err

}

// BroadcastingNodes is a free data retrieval call binding the contract method 0xcac5800a.
//
// Solidity: function broadcastingNodes(address ) view returns(string url, string name, uint256 stakedTokens, string location, uint256 maxStorageSpace, address addr)
func (_NodeManager *NodeManagerSession) BroadcastingNodes(arg0 common.Address) (struct {
	Url             string
	Name            string
	StakedTokens    *big.Int
	Location        string
	MaxStorageSpace *big.Int
	Addr            common.Address
}, error) {
	return _NodeManager.Contract.BroadcastingNodes(&_NodeManager.CallOpts, arg0)
}

// BroadcastingNodes is a free data retrieval call binding the contract method 0xcac5800a.
//
// Solidity: function broadcastingNodes(address ) view returns(string url, string name, uint256 stakedTokens, string location, uint256 maxStorageSpace, address addr)
func (_NodeManager *NodeManagerCallerSession) BroadcastingNodes(arg0 common.Address) (struct {
	Url             string
	Name            string
	StakedTokens    *big.Int
	Location        string
	MaxStorageSpace *big.Int
	Addr            common.Address
}, error) {
	return _NodeManager.Contract.BroadcastingNodes(&_NodeManager.CallOpts, arg0)
}

// GetBroadcastingNodes is a free data retrieval call binding the contract method 0x431ece75.
//
// Solidity: function getBroadcastingNodes() view returns((string,string,uint256,string,uint256,address)[] nodes)
func (_NodeManager *NodeManagerCaller) GetBroadcastingNodes(opts *bind.CallOpts) ([]NodeManagerNodeInfo, error) {
	var out []interface{}
	err := _NodeManager.contract.Call(opts, &out, "getBroadcastingNodes")

	if err != nil {
		return *new([]NodeManagerNodeInfo), err
	}

	out0 := *abi.ConvertType(out[0], new([]NodeManagerNodeInfo)).(*[]NodeManagerNodeInfo)

	return out0, err

}

// GetBroadcastingNodes is a free data retrieval call binding the contract method 0x431ece75.
//
// Solidity: function getBroadcastingNodes() view returns((string,string,uint256,string,uint256,address)[] nodes)
func (_NodeManager *NodeManagerSession) GetBroadcastingNodes() ([]NodeManagerNodeInfo, error) {
	return _NodeManager.Contract.GetBroadcastingNodes(&_NodeManager.CallOpts)
}

// GetBroadcastingNodes is a free data retrieval call binding the contract method 0x431ece75.
//
// Solidity: function getBroadcastingNodes() view returns((string,string,uint256,string,uint256,address)[] nodes)
func (_NodeManager *NodeManagerCallerSession) GetBroadcastingNodes() ([]NodeManagerNodeInfo, error) {
	return _NodeManager.Contract.GetBroadcastingNodes(&_NodeManager.CallOpts)
}

// GetStorageNodes is a free data retrieval call binding the contract method 0x2e67d259.
//
// Solidity: function getStorageNodes() view returns((string,string,uint256,string,uint256,address)[] nodes)
func (_NodeManager *NodeManagerCaller) GetStorageNodes(opts *bind.CallOpts) ([]NodeManagerNodeInfo, error) {
	var out []interface{}
	err := _NodeManager.contract.Call(opts, &out, "getStorageNodes")

	if err != nil {
		return *new([]NodeManagerNodeInfo), err
	}

	out0 := *abi.ConvertType(out[0], new([]NodeManagerNodeInfo)).(*[]NodeManagerNodeInfo)

	return out0, err

}

// GetStorageNodes is a free data retrieval call binding the contract method 0x2e67d259.
//
// Solidity: function getStorageNodes() view returns((string,string,uint256,string,uint256,address)[] nodes)
func (_NodeManager *NodeManagerSession) GetStorageNodes() ([]NodeManagerNodeInfo, error) {
	return _NodeManager.Contract.GetStorageNodes(&_NodeManager.CallOpts)
}

// GetStorageNodes is a free data retrieval call binding the contract method 0x2e67d259.
//
// Solidity: function getStorageNodes() view returns((string,string,uint256,string,uint256,address)[] nodes)
func (_NodeManager *NodeManagerCallerSession) GetStorageNodes() ([]NodeManagerNodeInfo, error) {
	return _NodeManager.Contract.GetStorageNodes(&_NodeManager.CallOpts)
}

// IsNodeBroadcast is a free data retrieval call binding the contract method 0x0bc4a3e0.
//
// Solidity: function isNodeBroadcast(address addr) view returns(bool)
func (_NodeManager *NodeManagerCaller) IsNodeBroadcast(opts *bind.CallOpts, addr common.Address) (bool, error) {
	var out []interface{}
	err := _NodeManager.contract.Call(opts, &out, "isNodeBroadcast", addr)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsNodeBroadcast is a free data retrieval call binding the contract method 0x0bc4a3e0.
//
// Solidity: function isNodeBroadcast(address addr) view returns(bool)
func (_NodeManager *NodeManagerSession) IsNodeBroadcast(addr common.Address) (bool, error) {
	return _NodeManager.Contract.IsNodeBroadcast(&_NodeManager.CallOpts, addr)
}

// IsNodeBroadcast is a free data retrieval call binding the contract method 0x0bc4a3e0.
//
// Solidity: function isNodeBroadcast(address addr) view returns(bool)
func (_NodeManager *NodeManagerCallerSession) IsNodeBroadcast(addr common.Address) (bool, error) {
	return _NodeManager.Contract.IsNodeBroadcast(&_NodeManager.CallOpts, addr)
}

// IsNodeStorage is a free data retrieval call binding the contract method 0x258d6848.
//
// Solidity: function isNodeStorage(address addr) view returns(bool)
func (_NodeManager *NodeManagerCaller) IsNodeStorage(opts *bind.CallOpts, addr common.Address) (bool, error) {
	var out []interface{}
	err := _NodeManager.contract.Call(opts, &out, "isNodeStorage", addr)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsNodeStorage is a free data retrieval call binding the contract method 0x258d6848.
//
// Solidity: function isNodeStorage(address addr) view returns(bool)
func (_NodeManager *NodeManagerSession) IsNodeStorage(addr common.Address) (bool, error) {
	return _NodeManager.Contract.IsNodeStorage(&_NodeManager.CallOpts, addr)
}

// IsNodeStorage is a free data retrieval call binding the contract method 0x258d6848.
//
// Solidity: function isNodeStorage(address addr) view returns(bool)
func (_NodeManager *NodeManagerCallerSession) IsNodeStorage(addr common.Address) (bool, error) {
	return _NodeManager.Contract.IsNodeStorage(&_NodeManager.CallOpts, addr)
}

// StorageNodeList is a free data retrieval call binding the contract method 0x7667d104.
//
// Solidity: function storageNodeList(uint256 ) view returns(address)
func (_NodeManager *NodeManagerCaller) StorageNodeList(opts *bind.CallOpts, arg0 *big.Int) (common.Address, error) {
	var out []interface{}
	err := _NodeManager.contract.Call(opts, &out, "storageNodeList", arg0)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// StorageNodeList is a free data retrieval call binding the contract method 0x7667d104.
//
// Solidity: function storageNodeList(uint256 ) view returns(address)
func (_NodeManager *NodeManagerSession) StorageNodeList(arg0 *big.Int) (common.Address, error) {
	return _NodeManager.Contract.StorageNodeList(&_NodeManager.CallOpts, arg0)
}

// StorageNodeList is a free data retrieval call binding the contract method 0x7667d104.
//
// Solidity: function storageNodeList(uint256 ) view returns(address)
func (_NodeManager *NodeManagerCallerSession) StorageNodeList(arg0 *big.Int) (common.Address, error) {
	return _NodeManager.Contract.StorageNodeList(&_NodeManager.CallOpts, arg0)
}

// StorageNodes is a free data retrieval call binding the contract method 0x8118eb33.
//
// Solidity: function storageNodes(address ) view returns(string url, string name, uint256 stakedTokens, string location, uint256 maxStorageSpace, address addr)
func (_NodeManager *NodeManagerCaller) StorageNodes(opts *bind.CallOpts, arg0 common.Address) (struct {
	Url             string
	Name            string
	StakedTokens    *big.Int
	Location        string
	MaxStorageSpace *big.Int
	Addr            common.Address
}, error) {
	var out []interface{}
	err := _NodeManager.contract.Call(opts, &out, "storageNodes", arg0)

	outstruct := new(struct {
		Url             string
		Name            string
		StakedTokens    *big.Int
		Location        string
		MaxStorageSpace *big.Int
		Addr            common.Address
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.Url = *abi.ConvertType(out[0], new(string)).(*string)
	outstruct.Name = *abi.ConvertType(out[1], new(string)).(*string)
	outstruct.StakedTokens = *abi.ConvertType(out[2], new(*big.Int)).(**big.Int)
	outstruct.Location = *abi.ConvertType(out[3], new(string)).(*string)
	outstruct.MaxStorageSpace = *abi.ConvertType(out[4], new(*big.Int)).(**big.Int)
	outstruct.Addr = *abi.ConvertType(out[5], new(common.Address)).(*common.Address)

	return *outstruct, err

}

// StorageNodes is a free data retrieval call binding the contract method 0x8118eb33.
//
// Solidity: function storageNodes(address ) view returns(string url, string name, uint256 stakedTokens, string location, uint256 maxStorageSpace, address addr)
func (_NodeManager *NodeManagerSession) StorageNodes(arg0 common.Address) (struct {
	Url             string
	Name            string
	StakedTokens    *big.Int
	Location        string
	MaxStorageSpace *big.Int
	Addr            common.Address
}, error) {
	return _NodeManager.Contract.StorageNodes(&_NodeManager.CallOpts, arg0)
}

// StorageNodes is a free data retrieval call binding the contract method 0x8118eb33.
//
// Solidity: function storageNodes(address ) view returns(string url, string name, uint256 stakedTokens, string location, uint256 maxStorageSpace, address addr)
func (_NodeManager *NodeManagerCallerSession) StorageNodes(arg0 common.Address) (struct {
	Url             string
	Name            string
	StakedTokens    *big.Int
	Location        string
	MaxStorageSpace *big.Int
	Addr            common.Address
}, error) {
	return _NodeManager.Contract.StorageNodes(&_NodeManager.CallOpts, arg0)
}

// Version is a free data retrieval call binding the contract method 0x54fd4d50.
//
// Solidity: function version() view returns(string)
func (_NodeManager *NodeManagerCaller) Version(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _NodeManager.contract.Call(opts, &out, "version")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// Version is a free data retrieval call binding the contract method 0x54fd4d50.
//
// Solidity: function version() view returns(string)
func (_NodeManager *NodeManagerSession) Version() (string, error) {
	return _NodeManager.Contract.Version(&_NodeManager.CallOpts)
}

// Version is a free data retrieval call binding the contract method 0x54fd4d50.
//
// Solidity: function version() view returns(string)
func (_NodeManager *NodeManagerCallerSession) Version() (string, error) {
	return _NodeManager.Contract.Version(&_NodeManager.CallOpts)
}

// Initialize is a paid mutator transaction binding the contract method 0x8129fc1c.
//
// Solidity: function initialize() returns()
func (_NodeManager *NodeManagerTransactor) Initialize(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _NodeManager.contract.Transact(opts, "initialize")
}

// Initialize is a paid mutator transaction binding the contract method 0x8129fc1c.
//
// Solidity: function initialize() returns()
func (_NodeManager *NodeManagerSession) Initialize() (*types.Transaction, error) {
	return _NodeManager.Contract.Initialize(&_NodeManager.TransactOpts)
}

// Initialize is a paid mutator transaction binding the contract method 0x8129fc1c.
//
// Solidity: function initialize() returns()
func (_NodeManager *NodeManagerTransactorSession) Initialize() (*types.Transaction, error) {
	return _NodeManager.Contract.Initialize(&_NodeManager.TransactOpts)
}

// RegisterBroadcastNode is a paid mutator transaction binding the contract method 0x312f1957.
//
// Solidity: function registerBroadcastNode((string,string,uint256,string,uint256,address) info) returns()
func (_NodeManager *NodeManagerTransactor) RegisterBroadcastNode(opts *bind.TransactOpts, info NodeManagerNodeInfo) (*types.Transaction, error) {
	return _NodeManager.contract.Transact(opts, "registerBroadcastNode", info)
}

// RegisterBroadcastNode is a paid mutator transaction binding the contract method 0x312f1957.
//
// Solidity: function registerBroadcastNode((string,string,uint256,string,uint256,address) info) returns()
func (_NodeManager *NodeManagerSession) RegisterBroadcastNode(info NodeManagerNodeInfo) (*types.Transaction, error) {
	return _NodeManager.Contract.RegisterBroadcastNode(&_NodeManager.TransactOpts, info)
}

// RegisterBroadcastNode is a paid mutator transaction binding the contract method 0x312f1957.
//
// Solidity: function registerBroadcastNode((string,string,uint256,string,uint256,address) info) returns()
func (_NodeManager *NodeManagerTransactorSession) RegisterBroadcastNode(info NodeManagerNodeInfo) (*types.Transaction, error) {
	return _NodeManager.Contract.RegisterBroadcastNode(&_NodeManager.TransactOpts, info)
}

// RegisterStorageNode is a paid mutator transaction binding the contract method 0xfc94101e.
//
// Solidity: function registerStorageNode((string,string,uint256,string,uint256,address) info) returns()
func (_NodeManager *NodeManagerTransactor) RegisterStorageNode(opts *bind.TransactOpts, info NodeManagerNodeInfo) (*types.Transaction, error) {
	return _NodeManager.contract.Transact(opts, "registerStorageNode", info)
}

// RegisterStorageNode is a paid mutator transaction binding the contract method 0xfc94101e.
//
// Solidity: function registerStorageNode((string,string,uint256,string,uint256,address) info) returns()
func (_NodeManager *NodeManagerSession) RegisterStorageNode(info NodeManagerNodeInfo) (*types.Transaction, error) {
	return _NodeManager.Contract.RegisterStorageNode(&_NodeManager.TransactOpts, info)
}

// RegisterStorageNode is a paid mutator transaction binding the contract method 0xfc94101e.
//
// Solidity: function registerStorageNode((string,string,uint256,string,uint256,address) info) returns()
func (_NodeManager *NodeManagerTransactorSession) RegisterStorageNode(info NodeManagerNodeInfo) (*types.Transaction, error) {
	return _NodeManager.Contract.RegisterStorageNode(&_NodeManager.TransactOpts, info)
}

// NodeManagerBroadcastNodeIterator is returned from FilterBroadcastNode and is used to iterate over the raw logs and unpacked data for BroadcastNode events raised by the NodeManager contract.
type NodeManagerBroadcastNodeIterator struct {
	Event *NodeManagerBroadcastNode // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *NodeManagerBroadcastNodeIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(NodeManagerBroadcastNode)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(NodeManagerBroadcastNode)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *NodeManagerBroadcastNodeIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *NodeManagerBroadcastNodeIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// NodeManagerBroadcastNode represents a BroadcastNode event raised by the NodeManager contract.
type NodeManagerBroadcastNode struct {
	Add          common.Address
	Url          string
	Name         string
	StakedTokens *big.Int
	Raw          types.Log // Blockchain specific contextual infos
}

// FilterBroadcastNode is a free log retrieval operation binding the contract event 0xf81ce16a7ccf3a5a010dfa9ea629627f1144fc81731e9d33059eb7bf82616815.
//
// Solidity: event BroadcastNode(address indexed add, string url, string name, uint256 stakedTokens)
func (_NodeManager *NodeManagerFilterer) FilterBroadcastNode(opts *bind.FilterOpts, add []common.Address) (*NodeManagerBroadcastNodeIterator, error) {

	var addRule []interface{}
	for _, addItem := range add {
		addRule = append(addRule, addItem)
	}

	logs, sub, err := _NodeManager.contract.FilterLogs(opts, "BroadcastNode", addRule)
	if err != nil {
		return nil, err
	}
	return &NodeManagerBroadcastNodeIterator{contract: _NodeManager.contract, event: "BroadcastNode", logs: logs, sub: sub}, nil
}

// WatchBroadcastNode is a free log subscription operation binding the contract event 0xf81ce16a7ccf3a5a010dfa9ea629627f1144fc81731e9d33059eb7bf82616815.
//
// Solidity: event BroadcastNode(address indexed add, string url, string name, uint256 stakedTokens)
func (_NodeManager *NodeManagerFilterer) WatchBroadcastNode(opts *bind.WatchOpts, sink chan<- *NodeManagerBroadcastNode, add []common.Address) (event.Subscription, error) {

	var addRule []interface{}
	for _, addItem := range add {
		addRule = append(addRule, addItem)
	}

	logs, sub, err := _NodeManager.contract.WatchLogs(opts, "BroadcastNode", addRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(NodeManagerBroadcastNode)
				if err := _NodeManager.contract.UnpackLog(event, "BroadcastNode", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseBroadcastNode is a log parse operation binding the contract event 0xf81ce16a7ccf3a5a010dfa9ea629627f1144fc81731e9d33059eb7bf82616815.
//
// Solidity: event BroadcastNode(address indexed add, string url, string name, uint256 stakedTokens)
func (_NodeManager *NodeManagerFilterer) ParseBroadcastNode(log types.Log) (*NodeManagerBroadcastNode, error) {
	event := new(NodeManagerBroadcastNode)
	if err := _NodeManager.contract.UnpackLog(event, "BroadcastNode", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// NodeManagerInitializedIterator is returned from FilterInitialized and is used to iterate over the raw logs and unpacked data for Initialized events raised by the NodeManager contract.
type NodeManagerInitializedIterator struct {
	Event *NodeManagerInitialized // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *NodeManagerInitializedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(NodeManagerInitialized)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(NodeManagerInitialized)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *NodeManagerInitializedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *NodeManagerInitializedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// NodeManagerInitialized represents a Initialized event raised by the NodeManager contract.
type NodeManagerInitialized struct {
	Version uint8
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterInitialized is a free log retrieval operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_NodeManager *NodeManagerFilterer) FilterInitialized(opts *bind.FilterOpts) (*NodeManagerInitializedIterator, error) {

	logs, sub, err := _NodeManager.contract.FilterLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return &NodeManagerInitializedIterator{contract: _NodeManager.contract, event: "Initialized", logs: logs, sub: sub}, nil
}

// WatchInitialized is a free log subscription operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_NodeManager *NodeManagerFilterer) WatchInitialized(opts *bind.WatchOpts, sink chan<- *NodeManagerInitialized) (event.Subscription, error) {

	logs, sub, err := _NodeManager.contract.WatchLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(NodeManagerInitialized)
				if err := _NodeManager.contract.UnpackLog(event, "Initialized", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseInitialized is a log parse operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_NodeManager *NodeManagerFilterer) ParseInitialized(log types.Log) (*NodeManagerInitialized, error) {
	event := new(NodeManagerInitialized)
	if err := _NodeManager.contract.UnpackLog(event, "Initialized", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// NodeManagerStorageNodeIterator is returned from FilterStorageNode and is used to iterate over the raw logs and unpacked data for StorageNode events raised by the NodeManager contract.
type NodeManagerStorageNodeIterator struct {
	Event *NodeManagerStorageNode // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *NodeManagerStorageNodeIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(NodeManagerStorageNode)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(NodeManagerStorageNode)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *NodeManagerStorageNodeIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *NodeManagerStorageNodeIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// NodeManagerStorageNode represents a StorageNode event raised by the NodeManager contract.
type NodeManagerStorageNode struct {
	Add          common.Address
	Url          string
	Name         string
	StakedTokens *big.Int
	Raw          types.Log // Blockchain specific contextual infos
}

// FilterStorageNode is a free log retrieval operation binding the contract event 0xf9d8c2f358d69a5e1c66d7fd47740827d4a975987462ad9a863ea0ad5b055f82.
//
// Solidity: event StorageNode(address indexed add, string url, string name, uint256 stakedTokens)
func (_NodeManager *NodeManagerFilterer) FilterStorageNode(opts *bind.FilterOpts, add []common.Address) (*NodeManagerStorageNodeIterator, error) {

	var addRule []interface{}
	for _, addItem := range add {
		addRule = append(addRule, addItem)
	}

	logs, sub, err := _NodeManager.contract.FilterLogs(opts, "StorageNode", addRule)
	if err != nil {
		return nil, err
	}
	return &NodeManagerStorageNodeIterator{contract: _NodeManager.contract, event: "StorageNode", logs: logs, sub: sub}, nil
}

// WatchStorageNode is a free log subscription operation binding the contract event 0xf9d8c2f358d69a5e1c66d7fd47740827d4a975987462ad9a863ea0ad5b055f82.
//
// Solidity: event StorageNode(address indexed add, string url, string name, uint256 stakedTokens)
func (_NodeManager *NodeManagerFilterer) WatchStorageNode(opts *bind.WatchOpts, sink chan<- *NodeManagerStorageNode, add []common.Address) (event.Subscription, error) {

	var addRule []interface{}
	for _, addItem := range add {
		addRule = append(addRule, addItem)
	}

	logs, sub, err := _NodeManager.contract.WatchLogs(opts, "StorageNode", addRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(NodeManagerStorageNode)
				if err := _NodeManager.contract.UnpackLog(event, "StorageNode", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseStorageNode is a log parse operation binding the contract event 0xf9d8c2f358d69a5e1c66d7fd47740827d4a975987462ad9a863ea0ad5b055f82.
//
// Solidity: event StorageNode(address indexed add, string url, string name, uint256 stakedTokens)
func (_NodeManager *NodeManagerFilterer) ParseStorageNode(log types.Log) (*NodeManagerStorageNode, error) {
	event := new(NodeManagerStorageNode)
	if err := _NodeManager.contract.UnpackLog(event, "StorageNode", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
