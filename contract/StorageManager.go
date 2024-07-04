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

// NameSpace is an auto generated low-level Go binding around an user-defined struct.
type NameSpace struct {
	Creator common.Address
	Addr    []common.Address
}

// NodeGroup is an auto generated low-level Go binding around an user-defined struct.
type NodeGroup struct {
	RequiredAmountOfSignatures *big.Int
	Addrs                      []common.Address
}

// StorageManagerMetaData contains all meta data concerning the StorageManager contract.
var StorageManagerMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint8\",\"name\":\"version\",\"type\":\"uint8\"}],\"name\":\"Initialized\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"creator\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"key\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"address[]\",\"name\":\"nodeAddresses\",\"type\":\"address[]\"}],\"name\":\"NameSpaceRegistered\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"creator\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"key\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"requiredAmountOfSignatures\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"address[]\",\"name\":\"nodeAddresses\",\"type\":\"address[]\"}],\"name\":\"NodeGroupRegistered\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"_key\",\"type\":\"bytes32\"}],\"name\":\"NAMESPACE\",\"outputs\":[{\"components\":[{\"internalType\":\"address\",\"name\":\"creator\",\"type\":\"address\"},{\"internalType\":\"address[]\",\"name\":\"addr\",\"type\":\"address[]\"}],\"internalType\":\"structNameSpace\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"_key\",\"type\":\"bytes32\"}],\"name\":\"NODEGROUP\",\"outputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"requiredAmountOfSignatures\",\"type\":\"uint256\"},{\"internalType\":\"address[]\",\"name\":\"addrs\",\"type\":\"address[]\"}],\"internalType\":\"structNodeGroup\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address[]\",\"name\":\"_nodeAddresses\",\"type\":\"address[]\"}],\"name\":\"getNameSpaceKey\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address[]\",\"name\":\"_nodeAddresses\",\"type\":\"address[]\"},{\"internalType\":\"uint256\",\"name\":\"_requiredAmountOfSignatures\",\"type\":\"uint256\"}],\"name\":\"getNodeGroupKey\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"stateMutability\":\"pure\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"contractNodeManager\",\"name\":\"_nodeManager\",\"type\":\"address\"}],\"name\":\"initialize\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"name\":\"nameSpace\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"creator\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"name\":\"nodeGroup\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"requiredAmountOfSignatures\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"nodeManager\",\"outputs\":[{\"internalType\":\"contractNodeManager\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address[]\",\"name\":\"_nodeAddresses\",\"type\":\"address[]\"}],\"name\":\"registerNameSpace\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"nameSpaceKey\",\"type\":\"bytes32\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_requiredAmountOfSignatures\",\"type\":\"uint256\"},{\"internalType\":\"address[]\",\"name\":\"_nodeAddresses\",\"type\":\"address[]\"}],\"name\":\"registerNodeGroup\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"nodeGroupKey\",\"type\":\"bytes32\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address[]\",\"name\":\"addresses\",\"type\":\"address[]\"}],\"name\":\"sortAddresses\",\"outputs\":[{\"internalType\":\"address[]\",\"name\":\"\",\"type\":\"address[]\"}],\"stateMutability\":\"pure\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"version\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]",
}

// StorageManagerABI is the input ABI used to generate the binding from.
// Deprecated: Use StorageManagerMetaData.ABI instead.
var StorageManagerABI = StorageManagerMetaData.ABI

// StorageManager is an auto generated Go binding around an Ethereum contract.
type StorageManager struct {
	StorageManagerCaller     // Read-only binding to the contract
	StorageManagerTransactor // Write-only binding to the contract
	StorageManagerFilterer   // Log filterer for contract events
}

// StorageManagerCaller is an auto generated read-only Go binding around an Ethereum contract.
type StorageManagerCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// StorageManagerTransactor is an auto generated write-only Go binding around an Ethereum contract.
type StorageManagerTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// StorageManagerFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type StorageManagerFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// StorageManagerSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type StorageManagerSession struct {
	Contract     *StorageManager   // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// StorageManagerCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type StorageManagerCallerSession struct {
	Contract *StorageManagerCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts         // Call options to use throughout this session
}

// StorageManagerTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type StorageManagerTransactorSession struct {
	Contract     *StorageManagerTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts         // Transaction auth options to use throughout this session
}

// StorageManagerRaw is an auto generated low-level Go binding around an Ethereum contract.
type StorageManagerRaw struct {
	Contract *StorageManager // Generic contract binding to access the raw methods on
}

// StorageManagerCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type StorageManagerCallerRaw struct {
	Contract *StorageManagerCaller // Generic read-only contract binding to access the raw methods on
}

// StorageManagerTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type StorageManagerTransactorRaw struct {
	Contract *StorageManagerTransactor // Generic write-only contract binding to access the raw methods on
}

// NewStorageManager creates a new instance of StorageManager, bound to a specific deployed contract.
func NewStorageManager(address common.Address, backend bind.ContractBackend) (*StorageManager, error) {
	contract, err := bindStorageManager(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &StorageManager{StorageManagerCaller: StorageManagerCaller{contract: contract}, StorageManagerTransactor: StorageManagerTransactor{contract: contract}, StorageManagerFilterer: StorageManagerFilterer{contract: contract}}, nil
}

// NewStorageManagerCaller creates a new read-only instance of StorageManager, bound to a specific deployed contract.
func NewStorageManagerCaller(address common.Address, caller bind.ContractCaller) (*StorageManagerCaller, error) {
	contract, err := bindStorageManager(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &StorageManagerCaller{contract: contract}, nil
}

// NewStorageManagerTransactor creates a new write-only instance of StorageManager, bound to a specific deployed contract.
func NewStorageManagerTransactor(address common.Address, transactor bind.ContractTransactor) (*StorageManagerTransactor, error) {
	contract, err := bindStorageManager(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &StorageManagerTransactor{contract: contract}, nil
}

// NewStorageManagerFilterer creates a new log filterer instance of StorageManager, bound to a specific deployed contract.
func NewStorageManagerFilterer(address common.Address, filterer bind.ContractFilterer) (*StorageManagerFilterer, error) {
	contract, err := bindStorageManager(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &StorageManagerFilterer{contract: contract}, nil
}

// bindStorageManager binds a generic wrapper to an already deployed contract.
func bindStorageManager(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := StorageManagerMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_StorageManager *StorageManagerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _StorageManager.Contract.StorageManagerCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_StorageManager *StorageManagerRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _StorageManager.Contract.StorageManagerTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_StorageManager *StorageManagerRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _StorageManager.Contract.StorageManagerTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_StorageManager *StorageManagerCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _StorageManager.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_StorageManager *StorageManagerTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _StorageManager.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_StorageManager *StorageManagerTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _StorageManager.Contract.contract.Transact(opts, method, params...)
}

// NAMESPACE is a free data retrieval call binding the contract method 0xc395aed9.
//
// Solidity: function NAMESPACE(bytes32 _key) view returns((address,address[]))
func (_StorageManager *StorageManagerCaller) NAMESPACE(opts *bind.CallOpts, _key [32]byte) (NameSpace, error) {
	var out []interface{}
	err := _StorageManager.contract.Call(opts, &out, "NAMESPACE", _key)

	if err != nil {
		return *new(NameSpace), err
	}

	out0 := *abi.ConvertType(out[0], new(NameSpace)).(*NameSpace)

	return out0, err

}

// NAMESPACE is a free data retrieval call binding the contract method 0xc395aed9.
//
// Solidity: function NAMESPACE(bytes32 _key) view returns((address,address[]))
func (_StorageManager *StorageManagerSession) NAMESPACE(_key [32]byte) (NameSpace, error) {
	return _StorageManager.Contract.NAMESPACE(&_StorageManager.CallOpts, _key)
}

// NAMESPACE is a free data retrieval call binding the contract method 0xc395aed9.
//
// Solidity: function NAMESPACE(bytes32 _key) view returns((address,address[]))
func (_StorageManager *StorageManagerCallerSession) NAMESPACE(_key [32]byte) (NameSpace, error) {
	return _StorageManager.Contract.NAMESPACE(&_StorageManager.CallOpts, _key)
}

// NODEGROUP is a free data retrieval call binding the contract method 0x9d1dcba7.
//
// Solidity: function NODEGROUP(bytes32 _key) view returns((uint256,address[]))
func (_StorageManager *StorageManagerCaller) NODEGROUP(opts *bind.CallOpts, _key [32]byte) (NodeGroup, error) {
	var out []interface{}
	err := _StorageManager.contract.Call(opts, &out, "NODEGROUP", _key)

	if err != nil {
		return *new(NodeGroup), err
	}

	out0 := *abi.ConvertType(out[0], new(NodeGroup)).(*NodeGroup)

	return out0, err

}

// NODEGROUP is a free data retrieval call binding the contract method 0x9d1dcba7.
//
// Solidity: function NODEGROUP(bytes32 _key) view returns((uint256,address[]))
func (_StorageManager *StorageManagerSession) NODEGROUP(_key [32]byte) (NodeGroup, error) {
	return _StorageManager.Contract.NODEGROUP(&_StorageManager.CallOpts, _key)
}

// NODEGROUP is a free data retrieval call binding the contract method 0x9d1dcba7.
//
// Solidity: function NODEGROUP(bytes32 _key) view returns((uint256,address[]))
func (_StorageManager *StorageManagerCallerSession) NODEGROUP(_key [32]byte) (NodeGroup, error) {
	return _StorageManager.Contract.NODEGROUP(&_StorageManager.CallOpts, _key)
}

// GetNameSpaceKey is a free data retrieval call binding the contract method 0x40684b3f.
//
// Solidity: function getNameSpaceKey(address[] _nodeAddresses) view returns(bytes32)
func (_StorageManager *StorageManagerCaller) GetNameSpaceKey(opts *bind.CallOpts, _nodeAddresses []common.Address) ([32]byte, error) {
	var out []interface{}
	err := _StorageManager.contract.Call(opts, &out, "getNameSpaceKey", _nodeAddresses)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// GetNameSpaceKey is a free data retrieval call binding the contract method 0x40684b3f.
//
// Solidity: function getNameSpaceKey(address[] _nodeAddresses) view returns(bytes32)
func (_StorageManager *StorageManagerSession) GetNameSpaceKey(_nodeAddresses []common.Address) ([32]byte, error) {
	return _StorageManager.Contract.GetNameSpaceKey(&_StorageManager.CallOpts, _nodeAddresses)
}

// GetNameSpaceKey is a free data retrieval call binding the contract method 0x40684b3f.
//
// Solidity: function getNameSpaceKey(address[] _nodeAddresses) view returns(bytes32)
func (_StorageManager *StorageManagerCallerSession) GetNameSpaceKey(_nodeAddresses []common.Address) ([32]byte, error) {
	return _StorageManager.Contract.GetNameSpaceKey(&_StorageManager.CallOpts, _nodeAddresses)
}

// GetNodeGroupKey is a free data retrieval call binding the contract method 0x2aadbf60.
//
// Solidity: function getNodeGroupKey(address[] _nodeAddresses, uint256 _requiredAmountOfSignatures) pure returns(bytes32)
func (_StorageManager *StorageManagerCaller) GetNodeGroupKey(opts *bind.CallOpts, _nodeAddresses []common.Address, _requiredAmountOfSignatures *big.Int) ([32]byte, error) {
	var out []interface{}
	err := _StorageManager.contract.Call(opts, &out, "getNodeGroupKey", _nodeAddresses, _requiredAmountOfSignatures)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// GetNodeGroupKey is a free data retrieval call binding the contract method 0x2aadbf60.
//
// Solidity: function getNodeGroupKey(address[] _nodeAddresses, uint256 _requiredAmountOfSignatures) pure returns(bytes32)
func (_StorageManager *StorageManagerSession) GetNodeGroupKey(_nodeAddresses []common.Address, _requiredAmountOfSignatures *big.Int) ([32]byte, error) {
	return _StorageManager.Contract.GetNodeGroupKey(&_StorageManager.CallOpts, _nodeAddresses, _requiredAmountOfSignatures)
}

// GetNodeGroupKey is a free data retrieval call binding the contract method 0x2aadbf60.
//
// Solidity: function getNodeGroupKey(address[] _nodeAddresses, uint256 _requiredAmountOfSignatures) pure returns(bytes32)
func (_StorageManager *StorageManagerCallerSession) GetNodeGroupKey(_nodeAddresses []common.Address, _requiredAmountOfSignatures *big.Int) ([32]byte, error) {
	return _StorageManager.Contract.GetNodeGroupKey(&_StorageManager.CallOpts, _nodeAddresses, _requiredAmountOfSignatures)
}

// NameSpace is a free data retrieval call binding the contract method 0x0bc2dae5.
//
// Solidity: function nameSpace(bytes32 ) view returns(address creator)
func (_StorageManager *StorageManagerCaller) NameSpace(opts *bind.CallOpts, arg0 [32]byte) (common.Address, error) {
	var out []interface{}
	err := _StorageManager.contract.Call(opts, &out, "nameSpace", arg0)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// NameSpace is a free data retrieval call binding the contract method 0x0bc2dae5.
//
// Solidity: function nameSpace(bytes32 ) view returns(address creator)
func (_StorageManager *StorageManagerSession) NameSpace(arg0 [32]byte) (common.Address, error) {
	return _StorageManager.Contract.NameSpace(&_StorageManager.CallOpts, arg0)
}

// NameSpace is a free data retrieval call binding the contract method 0x0bc2dae5.
//
// Solidity: function nameSpace(bytes32 ) view returns(address creator)
func (_StorageManager *StorageManagerCallerSession) NameSpace(arg0 [32]byte) (common.Address, error) {
	return _StorageManager.Contract.NameSpace(&_StorageManager.CallOpts, arg0)
}

// NodeGroup is a free data retrieval call binding the contract method 0xca9d9989.
//
// Solidity: function nodeGroup(bytes32 ) view returns(uint256 requiredAmountOfSignatures)
func (_StorageManager *StorageManagerCaller) NodeGroup(opts *bind.CallOpts, arg0 [32]byte) (*big.Int, error) {
	var out []interface{}
	err := _StorageManager.contract.Call(opts, &out, "nodeGroup", arg0)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// NodeGroup is a free data retrieval call binding the contract method 0xca9d9989.
//
// Solidity: function nodeGroup(bytes32 ) view returns(uint256 requiredAmountOfSignatures)
func (_StorageManager *StorageManagerSession) NodeGroup(arg0 [32]byte) (*big.Int, error) {
	return _StorageManager.Contract.NodeGroup(&_StorageManager.CallOpts, arg0)
}

// NodeGroup is a free data retrieval call binding the contract method 0xca9d9989.
//
// Solidity: function nodeGroup(bytes32 ) view returns(uint256 requiredAmountOfSignatures)
func (_StorageManager *StorageManagerCallerSession) NodeGroup(arg0 [32]byte) (*big.Int, error) {
	return _StorageManager.Contract.NodeGroup(&_StorageManager.CallOpts, arg0)
}

// NodeManager is a free data retrieval call binding the contract method 0x9bb5cd3f.
//
// Solidity: function nodeManager() view returns(address)
func (_StorageManager *StorageManagerCaller) NodeManager(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _StorageManager.contract.Call(opts, &out, "nodeManager")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// NodeManager is a free data retrieval call binding the contract method 0x9bb5cd3f.
//
// Solidity: function nodeManager() view returns(address)
func (_StorageManager *StorageManagerSession) NodeManager() (common.Address, error) {
	return _StorageManager.Contract.NodeManager(&_StorageManager.CallOpts)
}

// NodeManager is a free data retrieval call binding the contract method 0x9bb5cd3f.
//
// Solidity: function nodeManager() view returns(address)
func (_StorageManager *StorageManagerCallerSession) NodeManager() (common.Address, error) {
	return _StorageManager.Contract.NodeManager(&_StorageManager.CallOpts)
}

// SortAddresses is a free data retrieval call binding the contract method 0x2f32ed5c.
//
// Solidity: function sortAddresses(address[] addresses) pure returns(address[])
func (_StorageManager *StorageManagerCaller) SortAddresses(opts *bind.CallOpts, addresses []common.Address) ([]common.Address, error) {
	var out []interface{}
	err := _StorageManager.contract.Call(opts, &out, "sortAddresses", addresses)

	if err != nil {
		return *new([]common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new([]common.Address)).(*[]common.Address)

	return out0, err

}

// SortAddresses is a free data retrieval call binding the contract method 0x2f32ed5c.
//
// Solidity: function sortAddresses(address[] addresses) pure returns(address[])
func (_StorageManager *StorageManagerSession) SortAddresses(addresses []common.Address) ([]common.Address, error) {
	return _StorageManager.Contract.SortAddresses(&_StorageManager.CallOpts, addresses)
}

// SortAddresses is a free data retrieval call binding the contract method 0x2f32ed5c.
//
// Solidity: function sortAddresses(address[] addresses) pure returns(address[])
func (_StorageManager *StorageManagerCallerSession) SortAddresses(addresses []common.Address) ([]common.Address, error) {
	return _StorageManager.Contract.SortAddresses(&_StorageManager.CallOpts, addresses)
}

// Version is a free data retrieval call binding the contract method 0x54fd4d50.
//
// Solidity: function version() view returns(string)
func (_StorageManager *StorageManagerCaller) Version(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _StorageManager.contract.Call(opts, &out, "version")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// Version is a free data retrieval call binding the contract method 0x54fd4d50.
//
// Solidity: function version() view returns(string)
func (_StorageManager *StorageManagerSession) Version() (string, error) {
	return _StorageManager.Contract.Version(&_StorageManager.CallOpts)
}

// Version is a free data retrieval call binding the contract method 0x54fd4d50.
//
// Solidity: function version() view returns(string)
func (_StorageManager *StorageManagerCallerSession) Version() (string, error) {
	return _StorageManager.Contract.Version(&_StorageManager.CallOpts)
}

// Initialize is a paid mutator transaction binding the contract method 0xc4d66de8.
//
// Solidity: function initialize(address _nodeManager) returns()
func (_StorageManager *StorageManagerTransactor) Initialize(opts *bind.TransactOpts, _nodeManager common.Address) (*types.Transaction, error) {
	return _StorageManager.contract.Transact(opts, "initialize", _nodeManager)
}

// Initialize is a paid mutator transaction binding the contract method 0xc4d66de8.
//
// Solidity: function initialize(address _nodeManager) returns()
func (_StorageManager *StorageManagerSession) Initialize(_nodeManager common.Address) (*types.Transaction, error) {
	return _StorageManager.Contract.Initialize(&_StorageManager.TransactOpts, _nodeManager)
}

// Initialize is a paid mutator transaction binding the contract method 0xc4d66de8.
//
// Solidity: function initialize(address _nodeManager) returns()
func (_StorageManager *StorageManagerTransactorSession) Initialize(_nodeManager common.Address) (*types.Transaction, error) {
	return _StorageManager.Contract.Initialize(&_StorageManager.TransactOpts, _nodeManager)
}

// RegisterNameSpace is a paid mutator transaction binding the contract method 0x2d303103.
//
// Solidity: function registerNameSpace(address[] _nodeAddresses) returns(bytes32 nameSpaceKey)
func (_StorageManager *StorageManagerTransactor) RegisterNameSpace(opts *bind.TransactOpts, _nodeAddresses []common.Address) (*types.Transaction, error) {
	return _StorageManager.contract.Transact(opts, "registerNameSpace", _nodeAddresses)
}

// RegisterNameSpace is a paid mutator transaction binding the contract method 0x2d303103.
//
// Solidity: function registerNameSpace(address[] _nodeAddresses) returns(bytes32 nameSpaceKey)
func (_StorageManager *StorageManagerSession) RegisterNameSpace(_nodeAddresses []common.Address) (*types.Transaction, error) {
	return _StorageManager.Contract.RegisterNameSpace(&_StorageManager.TransactOpts, _nodeAddresses)
}

// RegisterNameSpace is a paid mutator transaction binding the contract method 0x2d303103.
//
// Solidity: function registerNameSpace(address[] _nodeAddresses) returns(bytes32 nameSpaceKey)
func (_StorageManager *StorageManagerTransactorSession) RegisterNameSpace(_nodeAddresses []common.Address) (*types.Transaction, error) {
	return _StorageManager.Contract.RegisterNameSpace(&_StorageManager.TransactOpts, _nodeAddresses)
}

// RegisterNodeGroup is a paid mutator transaction binding the contract method 0x405ba914.
//
// Solidity: function registerNodeGroup(uint256 _requiredAmountOfSignatures, address[] _nodeAddresses) returns(bytes32 nodeGroupKey)
func (_StorageManager *StorageManagerTransactor) RegisterNodeGroup(opts *bind.TransactOpts, _requiredAmountOfSignatures *big.Int, _nodeAddresses []common.Address) (*types.Transaction, error) {
	return _StorageManager.contract.Transact(opts, "registerNodeGroup", _requiredAmountOfSignatures, _nodeAddresses)
}

// RegisterNodeGroup is a paid mutator transaction binding the contract method 0x405ba914.
//
// Solidity: function registerNodeGroup(uint256 _requiredAmountOfSignatures, address[] _nodeAddresses) returns(bytes32 nodeGroupKey)
func (_StorageManager *StorageManagerSession) RegisterNodeGroup(_requiredAmountOfSignatures *big.Int, _nodeAddresses []common.Address) (*types.Transaction, error) {
	return _StorageManager.Contract.RegisterNodeGroup(&_StorageManager.TransactOpts, _requiredAmountOfSignatures, _nodeAddresses)
}

// RegisterNodeGroup is a paid mutator transaction binding the contract method 0x405ba914.
//
// Solidity: function registerNodeGroup(uint256 _requiredAmountOfSignatures, address[] _nodeAddresses) returns(bytes32 nodeGroupKey)
func (_StorageManager *StorageManagerTransactorSession) RegisterNodeGroup(_requiredAmountOfSignatures *big.Int, _nodeAddresses []common.Address) (*types.Transaction, error) {
	return _StorageManager.Contract.RegisterNodeGroup(&_StorageManager.TransactOpts, _requiredAmountOfSignatures, _nodeAddresses)
}

// StorageManagerInitializedIterator is returned from FilterInitialized and is used to iterate over the raw logs and unpacked data for Initialized events raised by the StorageManager contract.
type StorageManagerInitializedIterator struct {
	Event *StorageManagerInitialized // Event containing the contract specifics and raw log

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
func (it *StorageManagerInitializedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(StorageManagerInitialized)
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
		it.Event = new(StorageManagerInitialized)
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
func (it *StorageManagerInitializedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *StorageManagerInitializedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// StorageManagerInitialized represents a Initialized event raised by the StorageManager contract.
type StorageManagerInitialized struct {
	Version uint8
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterInitialized is a free log retrieval operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_StorageManager *StorageManagerFilterer) FilterInitialized(opts *bind.FilterOpts) (*StorageManagerInitializedIterator, error) {

	logs, sub, err := _StorageManager.contract.FilterLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return &StorageManagerInitializedIterator{contract: _StorageManager.contract, event: "Initialized", logs: logs, sub: sub}, nil
}

// WatchInitialized is a free log subscription operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_StorageManager *StorageManagerFilterer) WatchInitialized(opts *bind.WatchOpts, sink chan<- *StorageManagerInitialized) (event.Subscription, error) {

	logs, sub, err := _StorageManager.contract.WatchLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(StorageManagerInitialized)
				if err := _StorageManager.contract.UnpackLog(event, "Initialized", log); err != nil {
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
func (_StorageManager *StorageManagerFilterer) ParseInitialized(log types.Log) (*StorageManagerInitialized, error) {
	event := new(StorageManagerInitialized)
	if err := _StorageManager.contract.UnpackLog(event, "Initialized", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// StorageManagerNameSpaceRegisteredIterator is returned from FilterNameSpaceRegistered and is used to iterate over the raw logs and unpacked data for NameSpaceRegistered events raised by the StorageManager contract.
type StorageManagerNameSpaceRegisteredIterator struct {
	Event *StorageManagerNameSpaceRegistered // Event containing the contract specifics and raw log

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
func (it *StorageManagerNameSpaceRegisteredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(StorageManagerNameSpaceRegistered)
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
		it.Event = new(StorageManagerNameSpaceRegistered)
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
func (it *StorageManagerNameSpaceRegisteredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *StorageManagerNameSpaceRegisteredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// StorageManagerNameSpaceRegistered represents a NameSpaceRegistered event raised by the StorageManager contract.
type StorageManagerNameSpaceRegistered struct {
	Creator       common.Address
	Key           [32]byte
	NodeAddresses []common.Address
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterNameSpaceRegistered is a free log retrieval operation binding the contract event 0xa3ff5f51192abc1eec99b424555d9835de556a73a6d962f0c085c211efde08f8.
//
// Solidity: event NameSpaceRegistered(address indexed creator, bytes32 indexed key, address[] nodeAddresses)
func (_StorageManager *StorageManagerFilterer) FilterNameSpaceRegistered(opts *bind.FilterOpts, creator []common.Address, key [][32]byte) (*StorageManagerNameSpaceRegisteredIterator, error) {

	var creatorRule []interface{}
	for _, creatorItem := range creator {
		creatorRule = append(creatorRule, creatorItem)
	}
	var keyRule []interface{}
	for _, keyItem := range key {
		keyRule = append(keyRule, keyItem)
	}

	logs, sub, err := _StorageManager.contract.FilterLogs(opts, "NameSpaceRegistered", creatorRule, keyRule)
	if err != nil {
		return nil, err
	}
	return &StorageManagerNameSpaceRegisteredIterator{contract: _StorageManager.contract, event: "NameSpaceRegistered", logs: logs, sub: sub}, nil
}

// WatchNameSpaceRegistered is a free log subscription operation binding the contract event 0xa3ff5f51192abc1eec99b424555d9835de556a73a6d962f0c085c211efde08f8.
//
// Solidity: event NameSpaceRegistered(address indexed creator, bytes32 indexed key, address[] nodeAddresses)
func (_StorageManager *StorageManagerFilterer) WatchNameSpaceRegistered(opts *bind.WatchOpts, sink chan<- *StorageManagerNameSpaceRegistered, creator []common.Address, key [][32]byte) (event.Subscription, error) {

	var creatorRule []interface{}
	for _, creatorItem := range creator {
		creatorRule = append(creatorRule, creatorItem)
	}
	var keyRule []interface{}
	for _, keyItem := range key {
		keyRule = append(keyRule, keyItem)
	}

	logs, sub, err := _StorageManager.contract.WatchLogs(opts, "NameSpaceRegistered", creatorRule, keyRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(StorageManagerNameSpaceRegistered)
				if err := _StorageManager.contract.UnpackLog(event, "NameSpaceRegistered", log); err != nil {
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

// ParseNameSpaceRegistered is a log parse operation binding the contract event 0xa3ff5f51192abc1eec99b424555d9835de556a73a6d962f0c085c211efde08f8.
//
// Solidity: event NameSpaceRegistered(address indexed creator, bytes32 indexed key, address[] nodeAddresses)
func (_StorageManager *StorageManagerFilterer) ParseNameSpaceRegistered(log types.Log) (*StorageManagerNameSpaceRegistered, error) {
	event := new(StorageManagerNameSpaceRegistered)
	if err := _StorageManager.contract.UnpackLog(event, "NameSpaceRegistered", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// StorageManagerNodeGroupRegisteredIterator is returned from FilterNodeGroupRegistered and is used to iterate over the raw logs and unpacked data for NodeGroupRegistered events raised by the StorageManager contract.
type StorageManagerNodeGroupRegisteredIterator struct {
	Event *StorageManagerNodeGroupRegistered // Event containing the contract specifics and raw log

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
func (it *StorageManagerNodeGroupRegisteredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(StorageManagerNodeGroupRegistered)
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
		it.Event = new(StorageManagerNodeGroupRegistered)
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
func (it *StorageManagerNodeGroupRegisteredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *StorageManagerNodeGroupRegisteredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// StorageManagerNodeGroupRegistered represents a NodeGroupRegistered event raised by the StorageManager contract.
type StorageManagerNodeGroupRegistered struct {
	Creator                    common.Address
	Key                        [32]byte
	RequiredAmountOfSignatures *big.Int
	NodeAddresses              []common.Address
	Raw                        types.Log // Blockchain specific contextual infos
}

// FilterNodeGroupRegistered is a free log retrieval operation binding the contract event 0x743b3edc7d02714efe8b86b0641a0aae132bac4cd218903edaa2682fb22d1a76.
//
// Solidity: event NodeGroupRegistered(address indexed creator, bytes32 indexed key, uint256 requiredAmountOfSignatures, address[] nodeAddresses)
func (_StorageManager *StorageManagerFilterer) FilterNodeGroupRegistered(opts *bind.FilterOpts, creator []common.Address, key [][32]byte) (*StorageManagerNodeGroupRegisteredIterator, error) {

	var creatorRule []interface{}
	for _, creatorItem := range creator {
		creatorRule = append(creatorRule, creatorItem)
	}
	var keyRule []interface{}
	for _, keyItem := range key {
		keyRule = append(keyRule, keyItem)
	}

	logs, sub, err := _StorageManager.contract.FilterLogs(opts, "NodeGroupRegistered", creatorRule, keyRule)
	if err != nil {
		return nil, err
	}
	return &StorageManagerNodeGroupRegisteredIterator{contract: _StorageManager.contract, event: "NodeGroupRegistered", logs: logs, sub: sub}, nil
}

// WatchNodeGroupRegistered is a free log subscription operation binding the contract event 0x743b3edc7d02714efe8b86b0641a0aae132bac4cd218903edaa2682fb22d1a76.
//
// Solidity: event NodeGroupRegistered(address indexed creator, bytes32 indexed key, uint256 requiredAmountOfSignatures, address[] nodeAddresses)
func (_StorageManager *StorageManagerFilterer) WatchNodeGroupRegistered(opts *bind.WatchOpts, sink chan<- *StorageManagerNodeGroupRegistered, creator []common.Address, key [][32]byte) (event.Subscription, error) {

	var creatorRule []interface{}
	for _, creatorItem := range creator {
		creatorRule = append(creatorRule, creatorItem)
	}
	var keyRule []interface{}
	for _, keyItem := range key {
		keyRule = append(keyRule, keyItem)
	}

	logs, sub, err := _StorageManager.contract.WatchLogs(opts, "NodeGroupRegistered", creatorRule, keyRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(StorageManagerNodeGroupRegistered)
				if err := _StorageManager.contract.UnpackLog(event, "NodeGroupRegistered", log); err != nil {
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

// ParseNodeGroupRegistered is a log parse operation binding the contract event 0x743b3edc7d02714efe8b86b0641a0aae132bac4cd218903edaa2682fb22d1a76.
//
// Solidity: event NodeGroupRegistered(address indexed creator, bytes32 indexed key, uint256 requiredAmountOfSignatures, address[] nodeAddresses)
func (_StorageManager *StorageManagerFilterer) ParseNodeGroupRegistered(log types.Log) (*StorageManagerNodeGroupRegistered, error) {
	event := new(StorageManagerNodeGroupRegistered)
	if err := _StorageManager.contract.UnpackLog(event, "NodeGroupRegistered", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
