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
	ABI: "[{\"inputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint8\",\"name\":\"version\",\"type\":\"uint8\"}],\"name\":\"Initialized\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"id\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"creator\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"address[]\",\"name\":\"addr\",\"type\":\"address[]\"}],\"name\":\"NameSpaceCreated\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"user\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"key\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"address[]\",\"name\":\"addrs\",\"type\":\"address[]\"}],\"name\":\"NodeInfoStored\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_id\",\"type\":\"uint256\"}],\"name\":\"NAMESPACE\",\"outputs\":[{\"components\":[{\"internalType\":\"address\",\"name\":\"creator\",\"type\":\"address\"},{\"internalType\":\"address[]\",\"name\":\"addr\",\"type\":\"address[]\"}],\"internalType\":\"structNameSpace\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"_key\",\"type\":\"bytes32\"}],\"name\":\"NODEGROUP\",\"outputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"requiredAmountOfSignatures\",\"type\":\"uint256\"},{\"internalType\":\"address[]\",\"name\":\"addrs\",\"type\":\"address[]\"}],\"internalType\":\"structNodeGroup\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address[]\",\"name\":\"_addrs\",\"type\":\"address[]\"}],\"name\":\"createNameSpace\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address[]\",\"name\":\"_addrs\",\"type\":\"address[]\"},{\"internalType\":\"uint256\",\"name\":\"_requiredAmountOfSignatures\",\"type\":\"uint256\"}],\"name\":\"getKeyForAddresses\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"contractNodeManager\",\"name\":\"_nodeManager\",\"type\":\"address\"}],\"name\":\"initialize\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"nameSpace\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"creator\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"name\":\"nodeGroup\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"requiredAmountOfSignatures\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"nodeManager\",\"outputs\":[{\"internalType\":\"contractNodeManager\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"nonce\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_requiredAmountOfSignatures\",\"type\":\"uint256\"},{\"internalType\":\"address[]\",\"name\":\"_addrs\",\"type\":\"address[]\"}],\"name\":\"storeAddressMapping\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"ksHash\",\"type\":\"bytes32\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"version\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]",
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

// NAMESPACE is a free data retrieval call binding the contract method 0xc1f67d88.
//
// Solidity: function NAMESPACE(uint256 _id) view returns((address,address[]))
func (_StorageManager *StorageManagerCaller) NAMESPACE(opts *bind.CallOpts, _id *big.Int) (NameSpace, error) {
	var out []interface{}
	err := _StorageManager.contract.Call(opts, &out, "NAMESPACE", _id)

	if err != nil {
		return *new(NameSpace), err
	}

	out0 := *abi.ConvertType(out[0], new(NameSpace)).(*NameSpace)

	return out0, err

}

// NAMESPACE is a free data retrieval call binding the contract method 0xc1f67d88.
//
// Solidity: function NAMESPACE(uint256 _id) view returns((address,address[]))
func (_StorageManager *StorageManagerSession) NAMESPACE(_id *big.Int) (NameSpace, error) {
	return _StorageManager.Contract.NAMESPACE(&_StorageManager.CallOpts, _id)
}

// NAMESPACE is a free data retrieval call binding the contract method 0xc1f67d88.
//
// Solidity: function NAMESPACE(uint256 _id) view returns((address,address[]))
func (_StorageManager *StorageManagerCallerSession) NAMESPACE(_id *big.Int) (NameSpace, error) {
	return _StorageManager.Contract.NAMESPACE(&_StorageManager.CallOpts, _id)
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

// GetKeyForAddresses is a free data retrieval call binding the contract method 0x1bc97289.
//
// Solidity: function getKeyForAddresses(address[] _addrs, uint256 _requiredAmountOfSignatures) view returns(bytes32)
func (_StorageManager *StorageManagerCaller) GetKeyForAddresses(opts *bind.CallOpts, _addrs []common.Address, _requiredAmountOfSignatures *big.Int) ([32]byte, error) {
	var out []interface{}
	err := _StorageManager.contract.Call(opts, &out, "getKeyForAddresses", _addrs, _requiredAmountOfSignatures)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// GetKeyForAddresses is a free data retrieval call binding the contract method 0x1bc97289.
//
// Solidity: function getKeyForAddresses(address[] _addrs, uint256 _requiredAmountOfSignatures) view returns(bytes32)
func (_StorageManager *StorageManagerSession) GetKeyForAddresses(_addrs []common.Address, _requiredAmountOfSignatures *big.Int) ([32]byte, error) {
	return _StorageManager.Contract.GetKeyForAddresses(&_StorageManager.CallOpts, _addrs, _requiredAmountOfSignatures)
}

// GetKeyForAddresses is a free data retrieval call binding the contract method 0x1bc97289.
//
// Solidity: function getKeyForAddresses(address[] _addrs, uint256 _requiredAmountOfSignatures) view returns(bytes32)
func (_StorageManager *StorageManagerCallerSession) GetKeyForAddresses(_addrs []common.Address, _requiredAmountOfSignatures *big.Int) ([32]byte, error) {
	return _StorageManager.Contract.GetKeyForAddresses(&_StorageManager.CallOpts, _addrs, _requiredAmountOfSignatures)
}

// NameSpace is a free data retrieval call binding the contract method 0xb48fbcaf.
//
// Solidity: function nameSpace(uint256 ) view returns(address creator)
func (_StorageManager *StorageManagerCaller) NameSpace(opts *bind.CallOpts, arg0 *big.Int) (common.Address, error) {
	var out []interface{}
	err := _StorageManager.contract.Call(opts, &out, "nameSpace", arg0)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// NameSpace is a free data retrieval call binding the contract method 0xb48fbcaf.
//
// Solidity: function nameSpace(uint256 ) view returns(address creator)
func (_StorageManager *StorageManagerSession) NameSpace(arg0 *big.Int) (common.Address, error) {
	return _StorageManager.Contract.NameSpace(&_StorageManager.CallOpts, arg0)
}

// NameSpace is a free data retrieval call binding the contract method 0xb48fbcaf.
//
// Solidity: function nameSpace(uint256 ) view returns(address creator)
func (_StorageManager *StorageManagerCallerSession) NameSpace(arg0 *big.Int) (common.Address, error) {
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

// Nonce is a free data retrieval call binding the contract method 0xaffed0e0.
//
// Solidity: function nonce() view returns(uint256)
func (_StorageManager *StorageManagerCaller) Nonce(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _StorageManager.contract.Call(opts, &out, "nonce")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// Nonce is a free data retrieval call binding the contract method 0xaffed0e0.
//
// Solidity: function nonce() view returns(uint256)
func (_StorageManager *StorageManagerSession) Nonce() (*big.Int, error) {
	return _StorageManager.Contract.Nonce(&_StorageManager.CallOpts)
}

// Nonce is a free data retrieval call binding the contract method 0xaffed0e0.
//
// Solidity: function nonce() view returns(uint256)
func (_StorageManager *StorageManagerCallerSession) Nonce() (*big.Int, error) {
	return _StorageManager.Contract.Nonce(&_StorageManager.CallOpts)
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

// CreateNameSpace is a paid mutator transaction binding the contract method 0x8430726a.
//
// Solidity: function createNameSpace(address[] _addrs) returns(uint256)
func (_StorageManager *StorageManagerTransactor) CreateNameSpace(opts *bind.TransactOpts, _addrs []common.Address) (*types.Transaction, error) {
	return _StorageManager.contract.Transact(opts, "createNameSpace", _addrs)
}

// CreateNameSpace is a paid mutator transaction binding the contract method 0x8430726a.
//
// Solidity: function createNameSpace(address[] _addrs) returns(uint256)
func (_StorageManager *StorageManagerSession) CreateNameSpace(_addrs []common.Address) (*types.Transaction, error) {
	return _StorageManager.Contract.CreateNameSpace(&_StorageManager.TransactOpts, _addrs)
}

// CreateNameSpace is a paid mutator transaction binding the contract method 0x8430726a.
//
// Solidity: function createNameSpace(address[] _addrs) returns(uint256)
func (_StorageManager *StorageManagerTransactorSession) CreateNameSpace(_addrs []common.Address) (*types.Transaction, error) {
	return _StorageManager.Contract.CreateNameSpace(&_StorageManager.TransactOpts, _addrs)
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

// StoreAddressMapping is a paid mutator transaction binding the contract method 0xcc2e66ca.
//
// Solidity: function storeAddressMapping(uint256 _requiredAmountOfSignatures, address[] _addrs) returns(bytes32 ksHash)
func (_StorageManager *StorageManagerTransactor) StoreAddressMapping(opts *bind.TransactOpts, _requiredAmountOfSignatures *big.Int, _addrs []common.Address) (*types.Transaction, error) {
	return _StorageManager.contract.Transact(opts, "storeAddressMapping", _requiredAmountOfSignatures, _addrs)
}

// StoreAddressMapping is a paid mutator transaction binding the contract method 0xcc2e66ca.
//
// Solidity: function storeAddressMapping(uint256 _requiredAmountOfSignatures, address[] _addrs) returns(bytes32 ksHash)
func (_StorageManager *StorageManagerSession) StoreAddressMapping(_requiredAmountOfSignatures *big.Int, _addrs []common.Address) (*types.Transaction, error) {
	return _StorageManager.Contract.StoreAddressMapping(&_StorageManager.TransactOpts, _requiredAmountOfSignatures, _addrs)
}

// StoreAddressMapping is a paid mutator transaction binding the contract method 0xcc2e66ca.
//
// Solidity: function storeAddressMapping(uint256 _requiredAmountOfSignatures, address[] _addrs) returns(bytes32 ksHash)
func (_StorageManager *StorageManagerTransactorSession) StoreAddressMapping(_requiredAmountOfSignatures *big.Int, _addrs []common.Address) (*types.Transaction, error) {
	return _StorageManager.Contract.StoreAddressMapping(&_StorageManager.TransactOpts, _requiredAmountOfSignatures, _addrs)
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

// StorageManagerNameSpaceCreatedIterator is returned from FilterNameSpaceCreated and is used to iterate over the raw logs and unpacked data for NameSpaceCreated events raised by the StorageManager contract.
type StorageManagerNameSpaceCreatedIterator struct {
	Event *StorageManagerNameSpaceCreated // Event containing the contract specifics and raw log

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
func (it *StorageManagerNameSpaceCreatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(StorageManagerNameSpaceCreated)
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
		it.Event = new(StorageManagerNameSpaceCreated)
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
func (it *StorageManagerNameSpaceCreatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *StorageManagerNameSpaceCreatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// StorageManagerNameSpaceCreated represents a NameSpaceCreated event raised by the StorageManager contract.
type StorageManagerNameSpaceCreated struct {
	Id      *big.Int
	Creator common.Address
	Addr    []common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterNameSpaceCreated is a free log retrieval operation binding the contract event 0x525799b84736593cfb967a6c64dc3e091957a3d0bbbd13c3e8fb05896dc8bd43.
//
// Solidity: event NameSpaceCreated(uint256 indexed id, address indexed creator, address[] addr)
func (_StorageManager *StorageManagerFilterer) FilterNameSpaceCreated(opts *bind.FilterOpts, id []*big.Int, creator []common.Address) (*StorageManagerNameSpaceCreatedIterator, error) {

	var idRule []interface{}
	for _, idItem := range id {
		idRule = append(idRule, idItem)
	}
	var creatorRule []interface{}
	for _, creatorItem := range creator {
		creatorRule = append(creatorRule, creatorItem)
	}

	logs, sub, err := _StorageManager.contract.FilterLogs(opts, "NameSpaceCreated", idRule, creatorRule)
	if err != nil {
		return nil, err
	}
	return &StorageManagerNameSpaceCreatedIterator{contract: _StorageManager.contract, event: "NameSpaceCreated", logs: logs, sub: sub}, nil
}

// WatchNameSpaceCreated is a free log subscription operation binding the contract event 0x525799b84736593cfb967a6c64dc3e091957a3d0bbbd13c3e8fb05896dc8bd43.
//
// Solidity: event NameSpaceCreated(uint256 indexed id, address indexed creator, address[] addr)
func (_StorageManager *StorageManagerFilterer) WatchNameSpaceCreated(opts *bind.WatchOpts, sink chan<- *StorageManagerNameSpaceCreated, id []*big.Int, creator []common.Address) (event.Subscription, error) {

	var idRule []interface{}
	for _, idItem := range id {
		idRule = append(idRule, idItem)
	}
	var creatorRule []interface{}
	for _, creatorItem := range creator {
		creatorRule = append(creatorRule, creatorItem)
	}

	logs, sub, err := _StorageManager.contract.WatchLogs(opts, "NameSpaceCreated", idRule, creatorRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(StorageManagerNameSpaceCreated)
				if err := _StorageManager.contract.UnpackLog(event, "NameSpaceCreated", log); err != nil {
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

// ParseNameSpaceCreated is a log parse operation binding the contract event 0x525799b84736593cfb967a6c64dc3e091957a3d0bbbd13c3e8fb05896dc8bd43.
//
// Solidity: event NameSpaceCreated(uint256 indexed id, address indexed creator, address[] addr)
func (_StorageManager *StorageManagerFilterer) ParseNameSpaceCreated(log types.Log) (*StorageManagerNameSpaceCreated, error) {
	event := new(StorageManagerNameSpaceCreated)
	if err := _StorageManager.contract.UnpackLog(event, "NameSpaceCreated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// StorageManagerNodeInfoStoredIterator is returned from FilterNodeInfoStored and is used to iterate over the raw logs and unpacked data for NodeInfoStored events raised by the StorageManager contract.
type StorageManagerNodeInfoStoredIterator struct {
	Event *StorageManagerNodeInfoStored // Event containing the contract specifics and raw log

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
func (it *StorageManagerNodeInfoStoredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(StorageManagerNodeInfoStored)
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
		it.Event = new(StorageManagerNodeInfoStored)
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
func (it *StorageManagerNodeInfoStoredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *StorageManagerNodeInfoStoredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// StorageManagerNodeInfoStored represents a NodeInfoStored event raised by the StorageManager contract.
type StorageManagerNodeInfoStored struct {
	User  common.Address
	Key   [32]byte
	Addrs []common.Address
	Raw   types.Log // Blockchain specific contextual infos
}

// FilterNodeInfoStored is a free log retrieval operation binding the contract event 0x6685671d2938a50dd87b8e677e546f062f265876da9d3bd71007bb25ee5bc907.
//
// Solidity: event NodeInfoStored(address indexed user, bytes32 indexed key, address[] addrs)
func (_StorageManager *StorageManagerFilterer) FilterNodeInfoStored(opts *bind.FilterOpts, user []common.Address, key [][32]byte) (*StorageManagerNodeInfoStoredIterator, error) {

	var userRule []interface{}
	for _, userItem := range user {
		userRule = append(userRule, userItem)
	}
	var keyRule []interface{}
	for _, keyItem := range key {
		keyRule = append(keyRule, keyItem)
	}

	logs, sub, err := _StorageManager.contract.FilterLogs(opts, "NodeInfoStored", userRule, keyRule)
	if err != nil {
		return nil, err
	}
	return &StorageManagerNodeInfoStoredIterator{contract: _StorageManager.contract, event: "NodeInfoStored", logs: logs, sub: sub}, nil
}

// WatchNodeInfoStored is a free log subscription operation binding the contract event 0x6685671d2938a50dd87b8e677e546f062f265876da9d3bd71007bb25ee5bc907.
//
// Solidity: event NodeInfoStored(address indexed user, bytes32 indexed key, address[] addrs)
func (_StorageManager *StorageManagerFilterer) WatchNodeInfoStored(opts *bind.WatchOpts, sink chan<- *StorageManagerNodeInfoStored, user []common.Address, key [][32]byte) (event.Subscription, error) {

	var userRule []interface{}
	for _, userItem := range user {
		userRule = append(userRule, userItem)
	}
	var keyRule []interface{}
	for _, keyItem := range key {
		keyRule = append(keyRule, keyItem)
	}

	logs, sub, err := _StorageManager.contract.WatchLogs(opts, "NodeInfoStored", userRule, keyRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(StorageManagerNodeInfoStored)
				if err := _StorageManager.contract.UnpackLog(event, "NodeInfoStored", log); err != nil {
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

// ParseNodeInfoStored is a log parse operation binding the contract event 0x6685671d2938a50dd87b8e677e546f062f265876da9d3bd71007bb25ee5bc907.
//
// Solidity: event NodeInfoStored(address indexed user, bytes32 indexed key, address[] addrs)
func (_StorageManager *StorageManagerFilterer) ParseNodeInfoStored(log types.Log) (*StorageManagerNodeInfoStored, error) {
	event := new(StorageManagerNodeInfoStored)
	if err := _StorageManager.contract.UnpackLog(event, "NodeInfoStored", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
