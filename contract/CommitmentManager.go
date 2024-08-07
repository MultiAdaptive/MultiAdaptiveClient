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

// CommitmentManagerDADetails is an auto generated low-level Go binding around an user-defined struct.
type CommitmentManagerDADetails struct {
	Timestamp      *big.Int
	HashSignatures [32]byte
}

// PairingG1Point is an auto generated low-level Go binding around an user-defined struct.
type PairingG1Point struct {
	X *big.Int
	Y *big.Int
}

// CommitmentManagerMetaData contains all meta data concerning the CommitmentManager contract.
var CommitmentManagerMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"constructor\",\"inputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"baseFee\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"commitments\",\"inputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"X\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"Y\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"daDetails\",\"inputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"timestamp\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"hashSignatures\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getDADetailsByNonce\",\"inputs\":[{\"name\":\"_nonce\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"tuple\",\"internalType\":\"structCommitmentManager.DADetails\",\"components\":[{\"name\":\"timestamp\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"hashSignatures\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}]}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getDADetailsByUserAndIndex\",\"inputs\":[{\"name\":\"_user\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"_index\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"tuple\",\"internalType\":\"structCommitmentManager.DADetails\",\"components\":[{\"name\":\"timestamp\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"hashSignatures\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}]}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getNameSpaceCommitment\",\"inputs\":[{\"name\":\"_nameSpaceKey\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"_index\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"tuple\",\"internalType\":\"structPairing.G1Point\",\"components\":[{\"name\":\"X\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"Y\",\"type\":\"uint256\",\"internalType\":\"uint256\"}]}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getUserCommitment\",\"inputs\":[{\"name\":\"_user\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"_index\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"tuple\",\"internalType\":\"structPairing.G1Point\",\"components\":[{\"name\":\"X\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"Y\",\"type\":\"uint256\",\"internalType\":\"uint256\"}]}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"indices\",\"inputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"initialize\",\"inputs\":[{\"name\":\"_nodeManager\",\"type\":\"address\",\"internalType\":\"contractNodeManager\"},{\"name\":\"_storageManagement\",\"type\":\"address\",\"internalType\":\"contractStorageManager\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"nameSpaceCommitments\",\"inputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"X\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"Y\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"nameSpaceIndex\",\"inputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"nodeManager\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"contractNodeManager\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"nonce\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"owner\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"renounceOwnership\",\"inputs\":[],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"setBaseFee\",\"inputs\":[{\"name\":\"_newFee\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"storageManagement\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"contractStorageManager\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"submitCommitment\",\"inputs\":[{\"name\":\"_length\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"_timeout\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"_nameSpaceKey\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"_nodeGroupKey\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"_signatures\",\"type\":\"bytes[]\",\"internalType\":\"bytes[]\"},{\"name\":\"_commitment\",\"type\":\"tuple\",\"internalType\":\"structPairing.G1Point\",\"components\":[{\"name\":\"X\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"Y\",\"type\":\"uint256\",\"internalType\":\"uint256\"}]}],\"outputs\":[],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"transferOwnership\",\"inputs\":[{\"name\":\"newOwner\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"userCommitments\",\"inputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"X\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"Y\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"version\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"withdraw\",\"inputs\":[],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"event\",\"name\":\"Initialized\",\"inputs\":[{\"name\":\"version\",\"type\":\"uint8\",\"indexed\":false,\"internalType\":\"uint8\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"OwnershipTransferred\",\"inputs\":[{\"name\":\"previousOwner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"newOwner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"SendDACommitment\",\"inputs\":[{\"name\":\"commitment\",\"type\":\"tuple\",\"indexed\":false,\"internalType\":\"structPairing.G1Point\",\"components\":[{\"name\":\"X\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"Y\",\"type\":\"uint256\",\"internalType\":\"uint256\"}]},{\"name\":\"timestamp\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"},{\"name\":\"nonce\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"},{\"name\":\"index\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"},{\"name\":\"len\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"},{\"name\":\"nodeGroupKey\",\"type\":\"bytes32\",\"indexed\":false,\"internalType\":\"bytes32\"},{\"name\":\"nameSpaceKey\",\"type\":\"bytes32\",\"indexed\":false,\"internalType\":\"bytes32\"},{\"name\":\"signatures\",\"type\":\"bytes[]\",\"indexed\":false,\"internalType\":\"bytes[]\"}],\"anonymous\":false}]",
}

// CommitmentManagerABI is the input ABI used to generate the binding from.
// Deprecated: Use CommitmentManagerMetaData.ABI instead.
var CommitmentManagerABI = CommitmentManagerMetaData.ABI

// CommitmentManager is an auto generated Go binding around an Ethereum contract.
type CommitmentManager struct {
	CommitmentManagerCaller     // Read-only binding to the contract
	CommitmentManagerTransactor // Write-only binding to the contract
	CommitmentManagerFilterer   // Log filterer for contract events
}

// CommitmentManagerCaller is an auto generated read-only Go binding around an Ethereum contract.
type CommitmentManagerCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// CommitmentManagerTransactor is an auto generated write-only Go binding around an Ethereum contract.
type CommitmentManagerTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// CommitmentManagerFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type CommitmentManagerFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// CommitmentManagerSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type CommitmentManagerSession struct {
	Contract     *CommitmentManager // Generic contract binding to set the session for
	CallOpts     bind.CallOpts      // Call options to use throughout this session
	TransactOpts bind.TransactOpts  // Transaction auth options to use throughout this session
}

// CommitmentManagerCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type CommitmentManagerCallerSession struct {
	Contract *CommitmentManagerCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts            // Call options to use throughout this session
}

// CommitmentManagerTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type CommitmentManagerTransactorSession struct {
	Contract     *CommitmentManagerTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts            // Transaction auth options to use throughout this session
}

// CommitmentManagerRaw is an auto generated low-level Go binding around an Ethereum contract.
type CommitmentManagerRaw struct {
	Contract *CommitmentManager // Generic contract binding to access the raw methods on
}

// CommitmentManagerCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type CommitmentManagerCallerRaw struct {
	Contract *CommitmentManagerCaller // Generic read-only contract binding to access the raw methods on
}

// CommitmentManagerTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type CommitmentManagerTransactorRaw struct {
	Contract *CommitmentManagerTransactor // Generic write-only contract binding to access the raw methods on
}

// NewCommitmentManager creates a new instance of CommitmentManager, bound to a specific deployed contract.
func NewCommitmentManager(address common.Address, backend bind.ContractBackend) (*CommitmentManager, error) {
	contract, err := bindCommitmentManager(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &CommitmentManager{CommitmentManagerCaller: CommitmentManagerCaller{contract: contract}, CommitmentManagerTransactor: CommitmentManagerTransactor{contract: contract}, CommitmentManagerFilterer: CommitmentManagerFilterer{contract: contract}}, nil
}

// NewCommitmentManagerCaller creates a new read-only instance of CommitmentManager, bound to a specific deployed contract.
func NewCommitmentManagerCaller(address common.Address, caller bind.ContractCaller) (*CommitmentManagerCaller, error) {
	contract, err := bindCommitmentManager(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &CommitmentManagerCaller{contract: contract}, nil
}

// NewCommitmentManagerTransactor creates a new write-only instance of CommitmentManager, bound to a specific deployed contract.
func NewCommitmentManagerTransactor(address common.Address, transactor bind.ContractTransactor) (*CommitmentManagerTransactor, error) {
	contract, err := bindCommitmentManager(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &CommitmentManagerTransactor{contract: contract}, nil
}

// NewCommitmentManagerFilterer creates a new log filterer instance of CommitmentManager, bound to a specific deployed contract.
func NewCommitmentManagerFilterer(address common.Address, filterer bind.ContractFilterer) (*CommitmentManagerFilterer, error) {
	contract, err := bindCommitmentManager(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &CommitmentManagerFilterer{contract: contract}, nil
}

// bindCommitmentManager binds a generic wrapper to an already deployed contract.
func bindCommitmentManager(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := CommitmentManagerMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_CommitmentManager *CommitmentManagerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _CommitmentManager.Contract.CommitmentManagerCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_CommitmentManager *CommitmentManagerRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _CommitmentManager.Contract.CommitmentManagerTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_CommitmentManager *CommitmentManagerRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _CommitmentManager.Contract.CommitmentManagerTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_CommitmentManager *CommitmentManagerCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _CommitmentManager.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_CommitmentManager *CommitmentManagerTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _CommitmentManager.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_CommitmentManager *CommitmentManagerTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _CommitmentManager.Contract.contract.Transact(opts, method, params...)
}

// BaseFee is a free data retrieval call binding the contract method 0x6ef25c3a.
//
// Solidity: function baseFee() view returns(uint256)
func (_CommitmentManager *CommitmentManagerCaller) BaseFee(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _CommitmentManager.contract.Call(opts, &out, "baseFee")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// BaseFee is a free data retrieval call binding the contract method 0x6ef25c3a.
//
// Solidity: function baseFee() view returns(uint256)
func (_CommitmentManager *CommitmentManagerSession) BaseFee() (*big.Int, error) {
	return _CommitmentManager.Contract.BaseFee(&_CommitmentManager.CallOpts)
}

// BaseFee is a free data retrieval call binding the contract method 0x6ef25c3a.
//
// Solidity: function baseFee() view returns(uint256)
func (_CommitmentManager *CommitmentManagerCallerSession) BaseFee() (*big.Int, error) {
	return _CommitmentManager.Contract.BaseFee(&_CommitmentManager.CallOpts)
}

// Commitments is a free data retrieval call binding the contract method 0x49ce8997.
//
// Solidity: function commitments(uint256 ) view returns(uint256 X, uint256 Y)
func (_CommitmentManager *CommitmentManagerCaller) Commitments(opts *bind.CallOpts, arg0 *big.Int) (struct {
	X *big.Int
	Y *big.Int
}, error) {
	var out []interface{}
	err := _CommitmentManager.contract.Call(opts, &out, "commitments", arg0)

	outstruct := new(struct {
		X *big.Int
		Y *big.Int
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.X = *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)
	outstruct.Y = *abi.ConvertType(out[1], new(*big.Int)).(**big.Int)

	return *outstruct, err

}

// Commitments is a free data retrieval call binding the contract method 0x49ce8997.
//
// Solidity: function commitments(uint256 ) view returns(uint256 X, uint256 Y)
func (_CommitmentManager *CommitmentManagerSession) Commitments(arg0 *big.Int) (struct {
	X *big.Int
	Y *big.Int
}, error) {
	return _CommitmentManager.Contract.Commitments(&_CommitmentManager.CallOpts, arg0)
}

// Commitments is a free data retrieval call binding the contract method 0x49ce8997.
//
// Solidity: function commitments(uint256 ) view returns(uint256 X, uint256 Y)
func (_CommitmentManager *CommitmentManagerCallerSession) Commitments(arg0 *big.Int) (struct {
	X *big.Int
	Y *big.Int
}, error) {
	return _CommitmentManager.Contract.Commitments(&_CommitmentManager.CallOpts, arg0)
}

// DaDetails is a free data retrieval call binding the contract method 0x3f995b74.
//
// Solidity: function daDetails(bytes32 ) view returns(uint256 timestamp, bytes32 hashSignatures)
func (_CommitmentManager *CommitmentManagerCaller) DaDetails(opts *bind.CallOpts, arg0 [32]byte) (struct {
	Timestamp      *big.Int
	HashSignatures [32]byte
}, error) {
	var out []interface{}
	err := _CommitmentManager.contract.Call(opts, &out, "daDetails", arg0)

	outstruct := new(struct {
		Timestamp      *big.Int
		HashSignatures [32]byte
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.Timestamp = *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)
	outstruct.HashSignatures = *abi.ConvertType(out[1], new([32]byte)).(*[32]byte)

	return *outstruct, err

}

// DaDetails is a free data retrieval call binding the contract method 0x3f995b74.
//
// Solidity: function daDetails(bytes32 ) view returns(uint256 timestamp, bytes32 hashSignatures)
func (_CommitmentManager *CommitmentManagerSession) DaDetails(arg0 [32]byte) (struct {
	Timestamp      *big.Int
	HashSignatures [32]byte
}, error) {
	return _CommitmentManager.Contract.DaDetails(&_CommitmentManager.CallOpts, arg0)
}

// DaDetails is a free data retrieval call binding the contract method 0x3f995b74.
//
// Solidity: function daDetails(bytes32 ) view returns(uint256 timestamp, bytes32 hashSignatures)
func (_CommitmentManager *CommitmentManagerCallerSession) DaDetails(arg0 [32]byte) (struct {
	Timestamp      *big.Int
	HashSignatures [32]byte
}, error) {
	return _CommitmentManager.Contract.DaDetails(&_CommitmentManager.CallOpts, arg0)
}

// GetDADetailsByNonce is a free data retrieval call binding the contract method 0x99b659f1.
//
// Solidity: function getDADetailsByNonce(uint256 _nonce) view returns((uint256,bytes32))
func (_CommitmentManager *CommitmentManagerCaller) GetDADetailsByNonce(opts *bind.CallOpts, _nonce *big.Int) (CommitmentManagerDADetails, error) {
	var out []interface{}
	err := _CommitmentManager.contract.Call(opts, &out, "getDADetailsByNonce", _nonce)

	if err != nil {
		return *new(CommitmentManagerDADetails), err
	}

	out0 := *abi.ConvertType(out[0], new(CommitmentManagerDADetails)).(*CommitmentManagerDADetails)

	return out0, err

}

// GetDADetailsByNonce is a free data retrieval call binding the contract method 0x99b659f1.
//
// Solidity: function getDADetailsByNonce(uint256 _nonce) view returns((uint256,bytes32))
func (_CommitmentManager *CommitmentManagerSession) GetDADetailsByNonce(_nonce *big.Int) (CommitmentManagerDADetails, error) {
	return _CommitmentManager.Contract.GetDADetailsByNonce(&_CommitmentManager.CallOpts, _nonce)
}

// GetDADetailsByNonce is a free data retrieval call binding the contract method 0x99b659f1.
//
// Solidity: function getDADetailsByNonce(uint256 _nonce) view returns((uint256,bytes32))
func (_CommitmentManager *CommitmentManagerCallerSession) GetDADetailsByNonce(_nonce *big.Int) (CommitmentManagerDADetails, error) {
	return _CommitmentManager.Contract.GetDADetailsByNonce(&_CommitmentManager.CallOpts, _nonce)
}

// GetDADetailsByUserAndIndex is a free data retrieval call binding the contract method 0xb5caba68.
//
// Solidity: function getDADetailsByUserAndIndex(address _user, uint256 _index) view returns((uint256,bytes32))
func (_CommitmentManager *CommitmentManagerCaller) GetDADetailsByUserAndIndex(opts *bind.CallOpts, _user common.Address, _index *big.Int) (CommitmentManagerDADetails, error) {
	var out []interface{}
	err := _CommitmentManager.contract.Call(opts, &out, "getDADetailsByUserAndIndex", _user, _index)

	if err != nil {
		return *new(CommitmentManagerDADetails), err
	}

	out0 := *abi.ConvertType(out[0], new(CommitmentManagerDADetails)).(*CommitmentManagerDADetails)

	return out0, err

}

// GetDADetailsByUserAndIndex is a free data retrieval call binding the contract method 0xb5caba68.
//
// Solidity: function getDADetailsByUserAndIndex(address _user, uint256 _index) view returns((uint256,bytes32))
func (_CommitmentManager *CommitmentManagerSession) GetDADetailsByUserAndIndex(_user common.Address, _index *big.Int) (CommitmentManagerDADetails, error) {
	return _CommitmentManager.Contract.GetDADetailsByUserAndIndex(&_CommitmentManager.CallOpts, _user, _index)
}

// GetDADetailsByUserAndIndex is a free data retrieval call binding the contract method 0xb5caba68.
//
// Solidity: function getDADetailsByUserAndIndex(address _user, uint256 _index) view returns((uint256,bytes32))
func (_CommitmentManager *CommitmentManagerCallerSession) GetDADetailsByUserAndIndex(_user common.Address, _index *big.Int) (CommitmentManagerDADetails, error) {
	return _CommitmentManager.Contract.GetDADetailsByUserAndIndex(&_CommitmentManager.CallOpts, _user, _index)
}

// GetNameSpaceCommitment is a free data retrieval call binding the contract method 0x22bb340e.
//
// Solidity: function getNameSpaceCommitment(bytes32 _nameSpaceKey, uint256 _index) view returns((uint256,uint256))
func (_CommitmentManager *CommitmentManagerCaller) GetNameSpaceCommitment(opts *bind.CallOpts, _nameSpaceKey [32]byte, _index *big.Int) (PairingG1Point, error) {
	var out []interface{}
	err := _CommitmentManager.contract.Call(opts, &out, "getNameSpaceCommitment", _nameSpaceKey, _index)

	if err != nil {
		return *new(PairingG1Point), err
	}

	out0 := *abi.ConvertType(out[0], new(PairingG1Point)).(*PairingG1Point)

	return out0, err

}

// GetNameSpaceCommitment is a free data retrieval call binding the contract method 0x22bb340e.
//
// Solidity: function getNameSpaceCommitment(bytes32 _nameSpaceKey, uint256 _index) view returns((uint256,uint256))
func (_CommitmentManager *CommitmentManagerSession) GetNameSpaceCommitment(_nameSpaceKey [32]byte, _index *big.Int) (PairingG1Point, error) {
	return _CommitmentManager.Contract.GetNameSpaceCommitment(&_CommitmentManager.CallOpts, _nameSpaceKey, _index)
}

// GetNameSpaceCommitment is a free data retrieval call binding the contract method 0x22bb340e.
//
// Solidity: function getNameSpaceCommitment(bytes32 _nameSpaceKey, uint256 _index) view returns((uint256,uint256))
func (_CommitmentManager *CommitmentManagerCallerSession) GetNameSpaceCommitment(_nameSpaceKey [32]byte, _index *big.Int) (PairingG1Point, error) {
	return _CommitmentManager.Contract.GetNameSpaceCommitment(&_CommitmentManager.CallOpts, _nameSpaceKey, _index)
}

// GetUserCommitment is a free data retrieval call binding the contract method 0xfb75e675.
//
// Solidity: function getUserCommitment(address _user, uint256 _index) view returns((uint256,uint256))
func (_CommitmentManager *CommitmentManagerCaller) GetUserCommitment(opts *bind.CallOpts, _user common.Address, _index *big.Int) (PairingG1Point, error) {
	var out []interface{}
	err := _CommitmentManager.contract.Call(opts, &out, "getUserCommitment", _user, _index)

	if err != nil {
		return *new(PairingG1Point), err
	}

	out0 := *abi.ConvertType(out[0], new(PairingG1Point)).(*PairingG1Point)

	return out0, err

}

// GetUserCommitment is a free data retrieval call binding the contract method 0xfb75e675.
//
// Solidity: function getUserCommitment(address _user, uint256 _index) view returns((uint256,uint256))
func (_CommitmentManager *CommitmentManagerSession) GetUserCommitment(_user common.Address, _index *big.Int) (PairingG1Point, error) {
	return _CommitmentManager.Contract.GetUserCommitment(&_CommitmentManager.CallOpts, _user, _index)
}

// GetUserCommitment is a free data retrieval call binding the contract method 0xfb75e675.
//
// Solidity: function getUserCommitment(address _user, uint256 _index) view returns((uint256,uint256))
func (_CommitmentManager *CommitmentManagerCallerSession) GetUserCommitment(_user common.Address, _index *big.Int) (PairingG1Point, error) {
	return _CommitmentManager.Contract.GetUserCommitment(&_CommitmentManager.CallOpts, _user, _index)
}

// Indices is a free data retrieval call binding the contract method 0x5063e207.
//
// Solidity: function indices(address ) view returns(uint256)
func (_CommitmentManager *CommitmentManagerCaller) Indices(opts *bind.CallOpts, arg0 common.Address) (*big.Int, error) {
	var out []interface{}
	err := _CommitmentManager.contract.Call(opts, &out, "indices", arg0)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// Indices is a free data retrieval call binding the contract method 0x5063e207.
//
// Solidity: function indices(address ) view returns(uint256)
func (_CommitmentManager *CommitmentManagerSession) Indices(arg0 common.Address) (*big.Int, error) {
	return _CommitmentManager.Contract.Indices(&_CommitmentManager.CallOpts, arg0)
}

// Indices is a free data retrieval call binding the contract method 0x5063e207.
//
// Solidity: function indices(address ) view returns(uint256)
func (_CommitmentManager *CommitmentManagerCallerSession) Indices(arg0 common.Address) (*big.Int, error) {
	return _CommitmentManager.Contract.Indices(&_CommitmentManager.CallOpts, arg0)
}

// NameSpaceCommitments is a free data retrieval call binding the contract method 0x2119885b.
//
// Solidity: function nameSpaceCommitments(bytes32 , uint256 ) view returns(uint256 X, uint256 Y)
func (_CommitmentManager *CommitmentManagerCaller) NameSpaceCommitments(opts *bind.CallOpts, arg0 [32]byte, arg1 *big.Int) (struct {
	X *big.Int
	Y *big.Int
}, error) {
	var out []interface{}
	err := _CommitmentManager.contract.Call(opts, &out, "nameSpaceCommitments", arg0, arg1)

	outstruct := new(struct {
		X *big.Int
		Y *big.Int
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.X = *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)
	outstruct.Y = *abi.ConvertType(out[1], new(*big.Int)).(**big.Int)

	return *outstruct, err

}

// NameSpaceCommitments is a free data retrieval call binding the contract method 0x2119885b.
//
// Solidity: function nameSpaceCommitments(bytes32 , uint256 ) view returns(uint256 X, uint256 Y)
func (_CommitmentManager *CommitmentManagerSession) NameSpaceCommitments(arg0 [32]byte, arg1 *big.Int) (struct {
	X *big.Int
	Y *big.Int
}, error) {
	return _CommitmentManager.Contract.NameSpaceCommitments(&_CommitmentManager.CallOpts, arg0, arg1)
}

// NameSpaceCommitments is a free data retrieval call binding the contract method 0x2119885b.
//
// Solidity: function nameSpaceCommitments(bytes32 , uint256 ) view returns(uint256 X, uint256 Y)
func (_CommitmentManager *CommitmentManagerCallerSession) NameSpaceCommitments(arg0 [32]byte, arg1 *big.Int) (struct {
	X *big.Int
	Y *big.Int
}, error) {
	return _CommitmentManager.Contract.NameSpaceCommitments(&_CommitmentManager.CallOpts, arg0, arg1)
}

// NameSpaceIndex is a free data retrieval call binding the contract method 0xcdb2d8a8.
//
// Solidity: function nameSpaceIndex(bytes32 ) view returns(uint256)
func (_CommitmentManager *CommitmentManagerCaller) NameSpaceIndex(opts *bind.CallOpts, arg0 [32]byte) (*big.Int, error) {
	var out []interface{}
	err := _CommitmentManager.contract.Call(opts, &out, "nameSpaceIndex", arg0)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// NameSpaceIndex is a free data retrieval call binding the contract method 0xcdb2d8a8.
//
// Solidity: function nameSpaceIndex(bytes32 ) view returns(uint256)
func (_CommitmentManager *CommitmentManagerSession) NameSpaceIndex(arg0 [32]byte) (*big.Int, error) {
	return _CommitmentManager.Contract.NameSpaceIndex(&_CommitmentManager.CallOpts, arg0)
}

// NameSpaceIndex is a free data retrieval call binding the contract method 0xcdb2d8a8.
//
// Solidity: function nameSpaceIndex(bytes32 ) view returns(uint256)
func (_CommitmentManager *CommitmentManagerCallerSession) NameSpaceIndex(arg0 [32]byte) (*big.Int, error) {
	return _CommitmentManager.Contract.NameSpaceIndex(&_CommitmentManager.CallOpts, arg0)
}

// NodeManager is a free data retrieval call binding the contract method 0x9bb5cd3f.
//
// Solidity: function nodeManager() view returns(address)
func (_CommitmentManager *CommitmentManagerCaller) NodeManager(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _CommitmentManager.contract.Call(opts, &out, "nodeManager")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// NodeManager is a free data retrieval call binding the contract method 0x9bb5cd3f.
//
// Solidity: function nodeManager() view returns(address)
func (_CommitmentManager *CommitmentManagerSession) NodeManager() (common.Address, error) {
	return _CommitmentManager.Contract.NodeManager(&_CommitmentManager.CallOpts)
}

// NodeManager is a free data retrieval call binding the contract method 0x9bb5cd3f.
//
// Solidity: function nodeManager() view returns(address)
func (_CommitmentManager *CommitmentManagerCallerSession) NodeManager() (common.Address, error) {
	return _CommitmentManager.Contract.NodeManager(&_CommitmentManager.CallOpts)
}

// Nonce is a free data retrieval call binding the contract method 0xaffed0e0.
//
// Solidity: function nonce() view returns(uint256)
func (_CommitmentManager *CommitmentManagerCaller) Nonce(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _CommitmentManager.contract.Call(opts, &out, "nonce")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// Nonce is a free data retrieval call binding the contract method 0xaffed0e0.
//
// Solidity: function nonce() view returns(uint256)
func (_CommitmentManager *CommitmentManagerSession) Nonce() (*big.Int, error) {
	return _CommitmentManager.Contract.Nonce(&_CommitmentManager.CallOpts)
}

// Nonce is a free data retrieval call binding the contract method 0xaffed0e0.
//
// Solidity: function nonce() view returns(uint256)
func (_CommitmentManager *CommitmentManagerCallerSession) Nonce() (*big.Int, error) {
	return _CommitmentManager.Contract.Nonce(&_CommitmentManager.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_CommitmentManager *CommitmentManagerCaller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _CommitmentManager.contract.Call(opts, &out, "owner")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_CommitmentManager *CommitmentManagerSession) Owner() (common.Address, error) {
	return _CommitmentManager.Contract.Owner(&_CommitmentManager.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_CommitmentManager *CommitmentManagerCallerSession) Owner() (common.Address, error) {
	return _CommitmentManager.Contract.Owner(&_CommitmentManager.CallOpts)
}

// StorageManagement is a free data retrieval call binding the contract method 0x98bd4dee.
//
// Solidity: function storageManagement() view returns(address)
func (_CommitmentManager *CommitmentManagerCaller) StorageManagement(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _CommitmentManager.contract.Call(opts, &out, "storageManagement")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// StorageManagement is a free data retrieval call binding the contract method 0x98bd4dee.
//
// Solidity: function storageManagement() view returns(address)
func (_CommitmentManager *CommitmentManagerSession) StorageManagement() (common.Address, error) {
	return _CommitmentManager.Contract.StorageManagement(&_CommitmentManager.CallOpts)
}

// StorageManagement is a free data retrieval call binding the contract method 0x98bd4dee.
//
// Solidity: function storageManagement() view returns(address)
func (_CommitmentManager *CommitmentManagerCallerSession) StorageManagement() (common.Address, error) {
	return _CommitmentManager.Contract.StorageManagement(&_CommitmentManager.CallOpts)
}

// UserCommitments is a free data retrieval call binding the contract method 0x9a546848.
//
// Solidity: function userCommitments(address , uint256 ) view returns(uint256 X, uint256 Y)
func (_CommitmentManager *CommitmentManagerCaller) UserCommitments(opts *bind.CallOpts, arg0 common.Address, arg1 *big.Int) (struct {
	X *big.Int
	Y *big.Int
}, error) {
	var out []interface{}
	err := _CommitmentManager.contract.Call(opts, &out, "userCommitments", arg0, arg1)

	outstruct := new(struct {
		X *big.Int
		Y *big.Int
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.X = *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)
	outstruct.Y = *abi.ConvertType(out[1], new(*big.Int)).(**big.Int)

	return *outstruct, err

}

// UserCommitments is a free data retrieval call binding the contract method 0x9a546848.
//
// Solidity: function userCommitments(address , uint256 ) view returns(uint256 X, uint256 Y)
func (_CommitmentManager *CommitmentManagerSession) UserCommitments(arg0 common.Address, arg1 *big.Int) (struct {
	X *big.Int
	Y *big.Int
}, error) {
	return _CommitmentManager.Contract.UserCommitments(&_CommitmentManager.CallOpts, arg0, arg1)
}

// UserCommitments is a free data retrieval call binding the contract method 0x9a546848.
//
// Solidity: function userCommitments(address , uint256 ) view returns(uint256 X, uint256 Y)
func (_CommitmentManager *CommitmentManagerCallerSession) UserCommitments(arg0 common.Address, arg1 *big.Int) (struct {
	X *big.Int
	Y *big.Int
}, error) {
	return _CommitmentManager.Contract.UserCommitments(&_CommitmentManager.CallOpts, arg0, arg1)
}

// Version is a free data retrieval call binding the contract method 0x54fd4d50.
//
// Solidity: function version() view returns(string)
func (_CommitmentManager *CommitmentManagerCaller) Version(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _CommitmentManager.contract.Call(opts, &out, "version")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// Version is a free data retrieval call binding the contract method 0x54fd4d50.
//
// Solidity: function version() view returns(string)
func (_CommitmentManager *CommitmentManagerSession) Version() (string, error) {
	return _CommitmentManager.Contract.Version(&_CommitmentManager.CallOpts)
}

// Version is a free data retrieval call binding the contract method 0x54fd4d50.
//
// Solidity: function version() view returns(string)
func (_CommitmentManager *CommitmentManagerCallerSession) Version() (string, error) {
	return _CommitmentManager.Contract.Version(&_CommitmentManager.CallOpts)
}

// Initialize is a paid mutator transaction binding the contract method 0x485cc955.
//
// Solidity: function initialize(address _nodeManager, address _storageManagement) returns()
func (_CommitmentManager *CommitmentManagerTransactor) Initialize(opts *bind.TransactOpts, _nodeManager common.Address, _storageManagement common.Address) (*types.Transaction, error) {
	return _CommitmentManager.contract.Transact(opts, "initialize", _nodeManager, _storageManagement)
}

// Initialize is a paid mutator transaction binding the contract method 0x485cc955.
//
// Solidity: function initialize(address _nodeManager, address _storageManagement) returns()
func (_CommitmentManager *CommitmentManagerSession) Initialize(_nodeManager common.Address, _storageManagement common.Address) (*types.Transaction, error) {
	return _CommitmentManager.Contract.Initialize(&_CommitmentManager.TransactOpts, _nodeManager, _storageManagement)
}

// Initialize is a paid mutator transaction binding the contract method 0x485cc955.
//
// Solidity: function initialize(address _nodeManager, address _storageManagement) returns()
func (_CommitmentManager *CommitmentManagerTransactorSession) Initialize(_nodeManager common.Address, _storageManagement common.Address) (*types.Transaction, error) {
	return _CommitmentManager.Contract.Initialize(&_CommitmentManager.TransactOpts, _nodeManager, _storageManagement)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_CommitmentManager *CommitmentManagerTransactor) RenounceOwnership(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _CommitmentManager.contract.Transact(opts, "renounceOwnership")
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_CommitmentManager *CommitmentManagerSession) RenounceOwnership() (*types.Transaction, error) {
	return _CommitmentManager.Contract.RenounceOwnership(&_CommitmentManager.TransactOpts)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_CommitmentManager *CommitmentManagerTransactorSession) RenounceOwnership() (*types.Transaction, error) {
	return _CommitmentManager.Contract.RenounceOwnership(&_CommitmentManager.TransactOpts)
}

// SetBaseFee is a paid mutator transaction binding the contract method 0x46860698.
//
// Solidity: function setBaseFee(uint256 _newFee) returns()
func (_CommitmentManager *CommitmentManagerTransactor) SetBaseFee(opts *bind.TransactOpts, _newFee *big.Int) (*types.Transaction, error) {
	return _CommitmentManager.contract.Transact(opts, "setBaseFee", _newFee)
}

// SetBaseFee is a paid mutator transaction binding the contract method 0x46860698.
//
// Solidity: function setBaseFee(uint256 _newFee) returns()
func (_CommitmentManager *CommitmentManagerSession) SetBaseFee(_newFee *big.Int) (*types.Transaction, error) {
	return _CommitmentManager.Contract.SetBaseFee(&_CommitmentManager.TransactOpts, _newFee)
}

// SetBaseFee is a paid mutator transaction binding the contract method 0x46860698.
//
// Solidity: function setBaseFee(uint256 _newFee) returns()
func (_CommitmentManager *CommitmentManagerTransactorSession) SetBaseFee(_newFee *big.Int) (*types.Transaction, error) {
	return _CommitmentManager.Contract.SetBaseFee(&_CommitmentManager.TransactOpts, _newFee)
}

// SubmitCommitment is a paid mutator transaction binding the contract method 0x090ad065.
//
// Solidity: function submitCommitment(uint256 _length, uint256 _timeout, bytes32 _nameSpaceKey, bytes32 _nodeGroupKey, bytes[] _signatures, (uint256,uint256) _commitment) payable returns()
func (_CommitmentManager *CommitmentManagerTransactor) SubmitCommitment(opts *bind.TransactOpts, _length *big.Int, _timeout *big.Int, _nameSpaceKey [32]byte, _nodeGroupKey [32]byte, _signatures [][]byte, _commitment PairingG1Point) (*types.Transaction, error) {
	return _CommitmentManager.contract.Transact(opts, "submitCommitment", _length, _timeout, _nameSpaceKey, _nodeGroupKey, _signatures, _commitment)
}

// SubmitCommitment is a paid mutator transaction binding the contract method 0x090ad065.
//
// Solidity: function submitCommitment(uint256 _length, uint256 _timeout, bytes32 _nameSpaceKey, bytes32 _nodeGroupKey, bytes[] _signatures, (uint256,uint256) _commitment) payable returns()
func (_CommitmentManager *CommitmentManagerSession) SubmitCommitment(_length *big.Int, _timeout *big.Int, _nameSpaceKey [32]byte, _nodeGroupKey [32]byte, _signatures [][]byte, _commitment PairingG1Point) (*types.Transaction, error) {
	return _CommitmentManager.Contract.SubmitCommitment(&_CommitmentManager.TransactOpts, _length, _timeout, _nameSpaceKey, _nodeGroupKey, _signatures, _commitment)
}

// SubmitCommitment is a paid mutator transaction binding the contract method 0x090ad065.
//
// Solidity: function submitCommitment(uint256 _length, uint256 _timeout, bytes32 _nameSpaceKey, bytes32 _nodeGroupKey, bytes[] _signatures, (uint256,uint256) _commitment) payable returns()
func (_CommitmentManager *CommitmentManagerTransactorSession) SubmitCommitment(_length *big.Int, _timeout *big.Int, _nameSpaceKey [32]byte, _nodeGroupKey [32]byte, _signatures [][]byte, _commitment PairingG1Point) (*types.Transaction, error) {
	return _CommitmentManager.Contract.SubmitCommitment(&_CommitmentManager.TransactOpts, _length, _timeout, _nameSpaceKey, _nodeGroupKey, _signatures, _commitment)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_CommitmentManager *CommitmentManagerTransactor) TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
	return _CommitmentManager.contract.Transact(opts, "transferOwnership", newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_CommitmentManager *CommitmentManagerSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _CommitmentManager.Contract.TransferOwnership(&_CommitmentManager.TransactOpts, newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_CommitmentManager *CommitmentManagerTransactorSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _CommitmentManager.Contract.TransferOwnership(&_CommitmentManager.TransactOpts, newOwner)
}

// Withdraw is a paid mutator transaction binding the contract method 0x3ccfd60b.
//
// Solidity: function withdraw() returns()
func (_CommitmentManager *CommitmentManagerTransactor) Withdraw(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _CommitmentManager.contract.Transact(opts, "withdraw")
}

// Withdraw is a paid mutator transaction binding the contract method 0x3ccfd60b.
//
// Solidity: function withdraw() returns()
func (_CommitmentManager *CommitmentManagerSession) Withdraw() (*types.Transaction, error) {
	return _CommitmentManager.Contract.Withdraw(&_CommitmentManager.TransactOpts)
}

// Withdraw is a paid mutator transaction binding the contract method 0x3ccfd60b.
//
// Solidity: function withdraw() returns()
func (_CommitmentManager *CommitmentManagerTransactorSession) Withdraw() (*types.Transaction, error) {
	return _CommitmentManager.Contract.Withdraw(&_CommitmentManager.TransactOpts)
}

// CommitmentManagerInitializedIterator is returned from FilterInitialized and is used to iterate over the raw logs and unpacked data for Initialized events raised by the CommitmentManager contract.
type CommitmentManagerInitializedIterator struct {
	Event *CommitmentManagerInitialized // Event containing the contract specifics and raw log

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
func (it *CommitmentManagerInitializedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(CommitmentManagerInitialized)
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
		it.Event = new(CommitmentManagerInitialized)
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
func (it *CommitmentManagerInitializedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *CommitmentManagerInitializedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// CommitmentManagerInitialized represents a Initialized event raised by the CommitmentManager contract.
type CommitmentManagerInitialized struct {
	Version uint8
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterInitialized is a free log retrieval operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_CommitmentManager *CommitmentManagerFilterer) FilterInitialized(opts *bind.FilterOpts) (*CommitmentManagerInitializedIterator, error) {

	logs, sub, err := _CommitmentManager.contract.FilterLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return &CommitmentManagerInitializedIterator{contract: _CommitmentManager.contract, event: "Initialized", logs: logs, sub: sub}, nil
}

// WatchInitialized is a free log subscription operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_CommitmentManager *CommitmentManagerFilterer) WatchInitialized(opts *bind.WatchOpts, sink chan<- *CommitmentManagerInitialized) (event.Subscription, error) {

	logs, sub, err := _CommitmentManager.contract.WatchLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(CommitmentManagerInitialized)
				if err := _CommitmentManager.contract.UnpackLog(event, "Initialized", log); err != nil {
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
func (_CommitmentManager *CommitmentManagerFilterer) ParseInitialized(log types.Log) (*CommitmentManagerInitialized, error) {
	event := new(CommitmentManagerInitialized)
	if err := _CommitmentManager.contract.UnpackLog(event, "Initialized", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// CommitmentManagerOwnershipTransferredIterator is returned from FilterOwnershipTransferred and is used to iterate over the raw logs and unpacked data for OwnershipTransferred events raised by the CommitmentManager contract.
type CommitmentManagerOwnershipTransferredIterator struct {
	Event *CommitmentManagerOwnershipTransferred // Event containing the contract specifics and raw log

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
func (it *CommitmentManagerOwnershipTransferredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(CommitmentManagerOwnershipTransferred)
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
		it.Event = new(CommitmentManagerOwnershipTransferred)
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
func (it *CommitmentManagerOwnershipTransferredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *CommitmentManagerOwnershipTransferredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// CommitmentManagerOwnershipTransferred represents a OwnershipTransferred event raised by the CommitmentManager contract.
type CommitmentManagerOwnershipTransferred struct {
	PreviousOwner common.Address
	NewOwner      common.Address
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterOwnershipTransferred is a free log retrieval operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_CommitmentManager *CommitmentManagerFilterer) FilterOwnershipTransferred(opts *bind.FilterOpts, previousOwner []common.Address, newOwner []common.Address) (*CommitmentManagerOwnershipTransferredIterator, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _CommitmentManager.contract.FilterLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return &CommitmentManagerOwnershipTransferredIterator{contract: _CommitmentManager.contract, event: "OwnershipTransferred", logs: logs, sub: sub}, nil
}

// WatchOwnershipTransferred is a free log subscription operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_CommitmentManager *CommitmentManagerFilterer) WatchOwnershipTransferred(opts *bind.WatchOpts, sink chan<- *CommitmentManagerOwnershipTransferred, previousOwner []common.Address, newOwner []common.Address) (event.Subscription, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _CommitmentManager.contract.WatchLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(CommitmentManagerOwnershipTransferred)
				if err := _CommitmentManager.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
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

// ParseOwnershipTransferred is a log parse operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_CommitmentManager *CommitmentManagerFilterer) ParseOwnershipTransferred(log types.Log) (*CommitmentManagerOwnershipTransferred, error) {
	event := new(CommitmentManagerOwnershipTransferred)
	if err := _CommitmentManager.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// CommitmentManagerSendDACommitmentIterator is returned from FilterSendDACommitment and is used to iterate over the raw logs and unpacked data for SendDACommitment events raised by the CommitmentManager contract.
type CommitmentManagerSendDACommitmentIterator struct {
	Event *CommitmentManagerSendDACommitment // Event containing the contract specifics and raw log

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
func (it *CommitmentManagerSendDACommitmentIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(CommitmentManagerSendDACommitment)
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
		it.Event = new(CommitmentManagerSendDACommitment)
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
func (it *CommitmentManagerSendDACommitmentIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *CommitmentManagerSendDACommitmentIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// CommitmentManagerSendDACommitment represents a SendDACommitment event raised by the CommitmentManager contract.
type CommitmentManagerSendDACommitment struct {
	Commitment   PairingG1Point
	Timestamp    *big.Int
	Nonce        *big.Int
	Index        *big.Int
	Len          *big.Int
	NodeGroupKey [32]byte
	NameSpaceKey [32]byte
	Signatures   [][]byte
	Raw          types.Log // Blockchain specific contextual infos
}

// FilterSendDACommitment is a free log retrieval operation binding the contract event 0x9057e36780b94e7894f43d35979c11e9190d633cbc49e719ab96ad04f4eef3b4.
//
// Solidity: event SendDACommitment((uint256,uint256) commitment, uint256 timestamp, uint256 nonce, uint256 index, uint256 len, bytes32 nodeGroupKey, bytes32 nameSpaceKey, bytes[] signatures)
func (_CommitmentManager *CommitmentManagerFilterer) FilterSendDACommitment(opts *bind.FilterOpts) (*CommitmentManagerSendDACommitmentIterator, error) {

	logs, sub, err := _CommitmentManager.contract.FilterLogs(opts, "SendDACommitment")
	if err != nil {
		return nil, err
	}
	return &CommitmentManagerSendDACommitmentIterator{contract: _CommitmentManager.contract, event: "SendDACommitment", logs: logs, sub: sub}, nil
}

// WatchSendDACommitment is a free log subscription operation binding the contract event 0x9057e36780b94e7894f43d35979c11e9190d633cbc49e719ab96ad04f4eef3b4.
//
// Solidity: event SendDACommitment((uint256,uint256) commitment, uint256 timestamp, uint256 nonce, uint256 index, uint256 len, bytes32 nodeGroupKey, bytes32 nameSpaceKey, bytes[] signatures)
func (_CommitmentManager *CommitmentManagerFilterer) WatchSendDACommitment(opts *bind.WatchOpts, sink chan<- *CommitmentManagerSendDACommitment) (event.Subscription, error) {

	logs, sub, err := _CommitmentManager.contract.WatchLogs(opts, "SendDACommitment")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(CommitmentManagerSendDACommitment)
				if err := _CommitmentManager.contract.UnpackLog(event, "SendDACommitment", log); err != nil {
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

// ParseSendDACommitment is a log parse operation binding the contract event 0x9057e36780b94e7894f43d35979c11e9190d633cbc49e719ab96ad04f4eef3b4.
//
// Solidity: event SendDACommitment((uint256,uint256) commitment, uint256 timestamp, uint256 nonce, uint256 index, uint256 len, bytes32 nodeGroupKey, bytes32 nameSpaceKey, bytes[] signatures)
func (_CommitmentManager *CommitmentManagerFilterer) ParseSendDACommitment(log types.Log) (*CommitmentManagerSendDACommitment, error) {
	event := new(CommitmentManagerSendDACommitment)
	if err := _CommitmentManager.contract.UnpackLog(event, "SendDACommitment", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
