# RewardyDualEntryAccount

**RewardyDualEntryAccount** is a minimal smart account that supports both:
- **EIP‑7702 (type‑4)** off‑chain signed batched execution, and
- **ERC‑4337 v0.8** account abstraction flow (with an EntryPoint).

The contract exposes simple batch execution methods for 7702, and the standard
`validateUserOp`/execution hooks for 4337. It is intended as a learning
reference and a slim starting point for production accounts.

> ⚠️ **Security note**: The included `validateUserOp` returns `0` (always succeeds).
Replace the validation with a real scheme before mainnet use (e.g., EOA sigs,
session keys, guardians, etc.).

---

## Table of Contents

- [Design Goals](#design-goals)
- [What You Get](#what-you-get)
- [Contract Addresses & Constructor](#contract-addresses--constructor)
- [Data Structures](#data-structures)
- [Events](#events)
- [Public API](#public-api)
  - [4337 path](#4337-path)
  - [7702 path](#7702-path)
  - [Views](#views)
- [7702 Signature Scheme](#7702-signature-scheme)
- [Usage Examples](#usage-examples)
  - [Deploy (Hardhat/Foundry)](#deploy-hardhatfoundry)
  - [Call 7702 executeWithAuthorization (ethers.js)](#call-7702-executewithauthorization-ethersjs)
  - [Call 4337 via a Bundler](#call-4337-via-a-bundler)
- [Testing Tips](#testing-tips)
- [Limitations & TODO](#limitations--todo)
- [License](#license)

---

## Design Goals

- **Dual entry**: same account can be used by an 4337 EntryPoint *or* via direct
  EIP‑7702 style signed calls.
- **Small surface**: keep code easy to audit and extend.
- **Explicit fees** for 7702 path (ETH or ERC‑20) with a simple fee struct.
- **Clear hooks** to replace the demo validation logic with your own.

## What You Get

- Minimal 4337 v0.8 compatibility:
  - `validateUserOp(PackedUserOperation, ...)` stub.
  - `execute/executeBatch` guarded by `onlyEP` (EntryPoint‑only).
- Minimal 7702 type‑4 flow:
  - Off‑chain signature over a deterministic digest
  - `executeWithAuthorization` (no fee) / `executeWithFee` (ETH or ERC‑20)
  - Nonce tracking & batch execution

## Contract Addresses & Constructor

```solidity
constructor(address entryPoint_, address altEntryPoint_)
```

- `ENTRY_POINT`: Canonical 4337 EntryPoint (v0.8) used at runtime.
- `ALT_ENTRY_POINT`: Optional alternate EP (some bundlers simulate with a
  different address). Pass `address(0)` if unused.

You can deploy distinct instances per chain and record addresses in your app
configuration (e.g., via environment variables).

## Data Structures

```solidity
struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits; // (verificationGasLimit, callGasLimit)
    uint256 preVerificationGas;
    bytes32 gasFees;          // (maxPriorityFeePerGas, maxFeePerGas)
    bytes paymasterAndData;
    bytes signature;
}

struct BatchCall { address target; uint256 value; bytes data; }
struct InternalCall { address to; uint256 value; bytes data; }

struct Fee {
    address token;   // 0x0 = ETH
    uint256 amount;  // 0 = no fee
    address receiver;
}
```

- `nonce (public uint256)`: 7702 batch nonce (incremented on each batch).

## Events

```solidity
event CallExecuted(address indexed to, uint256 value, bytes data);
event BatchExecuted(uint256 indexed nonce, uint256 callCount, bytes32 callsHash);
event FeeCharged(address indexed token, address indexed to, uint256 amount);
```

## Public API

### 4337 path

- `function validateUserOp(PackedUserOperation calldata, bytes32, uint256 missingAccountFunds) external onlyEP returns (uint256)`
  - **Demo**: always returns `0`. If `missingAccountFunds > 0`, sends ETH to the EP.
- `function execute(address target, uint256 value, bytes data) external payable onlyEP`
- `function executeBatch(BatchCall[] calldata calls) external payable onlyEP`

### 7702 path

- `function executeWithAuthorization(InternalCall[] calldata calls, uint256 deadline, bytes calldata signature) external payable`
- `function executeWithFee(InternalCall[] calldata calls, Fee calldata fee, uint256 deadline, bytes calldata signature) external payable`
- `function executeDirect(InternalCall[] calldata calls) external payable`
  - Self‑call only (`msg.sender == address(this)`), for meta‑flows.

### Views

- `function entryPoint() external view returns (IEntryPoint)`
- `function altEntryPoint() external view returns (address)`
- `function getNonce() external view returns (uint256)`
- `function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4)`
  - EIP‑1271 style: returns `0x1626ba7e` if `ECDSA.recover(hash, sig) == address(this)`.

## 7702 Signature Scheme

For a batch of `InternalCall[] calls` and a `Fee fee`:

```
callsHash = keccak256(abi.encodePacked(calls[i].to, calls[i].value, calls[i].data ...))
digest    = keccak256(abi.encode(callsHash, fee.token, fee.amount, fee.receiver, nonce, deadline))
ethHash   = ECDSA.toEthSignedMessageHash(digest)  // MessageHashUtils
recovered = ECDSA.recover(ethHash, signature)
require(recovered == address(this))
```

- `nonce` is the public state variable and is incremented on each batch.
- `deadline` is a unix timestamp and must be `>= block.timestamp`.
- For ETH fee: `fee.token = address(0)`; for ERC‑20, pass the token address.

> **Note**: The equality check against `address(this)` models EIP‑7702 type‑4,
> where the account address is derived from a user’s ephemeral EOA for the
> validity period. Ensure your off‑chain signer and address mapping are
> configured correctly for your 7702 flow.

## Usage Examples

### Deploy (Hardhat/Foundry)

```solidity
// Hardhat deploy snippet
const ENTRY_POINT = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789";
const ALT_EP      = "0x0000000000000000000000000000000000000000";

const factory = await ethers.getContractFactory("RewardyDualEntryAccount");
const acc = await factory.deploy(ENTRY_POINT, ALT_EP);
await acc.deployed();
console.log("RewardyDualEntryAccount =", acc.address);
```

### Call 7702 `executeWithAuthorization` (ethers.js)

```ts
import { ethers } from "ethers";

// Build InternalCall[]
const calls = [
  { to: USDC, value: 0, data: iface.encodeFunctionData("approve", [SPENDER, amount]) },
  { to: MARKET, value: 0, data: iface.encodeFunctionData("deposit", [amount]) },
];

// Compute digest (must exactly match contract)
const callsHash = ethers.keccak256(
  ethers.AbiCoder.defaultAbiCoder().encode(
    ["bytes"],
    [ethers.concat(calls.map(c => ethers.solidityPacked(["address","uint256","bytes"], [c.to, c.value, c.data])))]
  )
);

const fee = { token: ethers.ZeroAddress, amount: 0, receiver: ethers.ZeroAddress };
const nonce = await acc.getNonce();
const deadline = Math.floor(Date.now()/1000) + 600;

const digest = ethers.keccak256(
  ethers.AbiCoder.defaultAbiCoder().encode(
    ["bytes32","address","uint256","address","uint256","uint256"],
    [callsHash, fee.token, fee.amount, fee.receiver, nonce, deadline]
  )
);

// EIP‑191 eth_sign
const ethHash = ethers.hashMessage(ethers.getBytes(digest));
const signature = await signer.signMessage(ethers.getBytes(digest));

// Send
await acc.executeWithAuthorization(calls, deadline, signature);
```

### Call 4337 via a Bundler

- Construct a `PackedUserOperation` with `sender = accountAddress`, `callData`
  encoding of `execute`/`executeBatch`, and your gas fields.
- Submit to a v0.8‑compatible bundler (e.g., `eth_sendUserOperation`).

Your off‑chain infra can use `eth_supportedEntryPoints` to discover the EP
address that the bundler expects for simulation. The contract also exposes
`ENTRY_POINT` and (optionally) `ALT_ENTRY_POINT` for clarity.

## Testing Tips

- Add unit tests that:
  - verify `nonce` increments,
  - verify signature malleability is rejected,
  - cover fee flows for ETH and ERC‑20,
  - check `onlyEP` paths revert for non‑EP senders.
- For 4337, integrate a local bundler or mock the EP call pattern.
- Consider adding a reentrancy guard if you extend the execution model.

## Limitations & TODO

- `validateUserOp` is a stub (always succeeds). Replace with your policy.
- No built‑in upgradeability, key rotation, guardians, session keys, or
  spend limits—add them if required.
- `_executeBatch` uses raw `.call`; review and harden for your use case.

## License

MIT
