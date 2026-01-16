# Mero-8k-PoC

## Summary

| Item | Value |
|------|-------|
| **Target** | Mero ETH Pool |
| **Vulnerability** | CEI Pattern Violation + Storage Manipulation |
| **Funds at Risk** | ~2.498 ETH |
| **Funds Drained** | ~2.498 ETH (99.99%) |

---

## Contracts

| Contract | Address |
|----------|---------|
| EthPool (LiquidityPool) | `0x19C674f7679c33f5c0248D9F736b2726447c41cF` |
| LP Token | `0x582677Cb94F25D4B68DbcBbAF0f8D9CBdc3fbA0e` |
| Staker | `0xe6B64F8C109dAEb5b8Ce6D528f88eeD65eAFd4Ae` |
| Vault | `0x2F1682c6782C58d2E95E4165328180F9d65A6B6D` |
| Strategy | `0x01F6a390Aa33dC42da011060Be8119345d4EbC43` |

---

## State Analysis

```
Pool ETH Balance:      2,498,402,345,675,643,414 wei (~2.498 ETH)
LP Token Total Supply: 2,330,350,505,679,914,526 wei (~2.33 LP)
LP Tokens Staked:      1,071,748,116,861,928,195 wei (~1.07 LP)
LP Tokens Non-Staked:  1,258,602,388,817,986,331 wei (~1.26 LP)
Exchange Rate:         1.072 (1 LP = 1.072 ETH)
Pool Status:           SHUTDOWN
```

---

## Root cause

### CEI Pattern Violation in `unstakeFor`

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

### Unsafe ETH Transfer

**File:** `EthPool.sol:2913-2916`

```solidity
function _doTransferOut(address payable to, uint256 amount) internal override {
    (bool success, ) = to.call{value: amount}("");
    require(success, Error.FAILED_TRANSFER);
}
```

**Issue:** ETH transfer via low-level call can trigger the `receive()` function of an attacker contract, creating a reentrancy vector.

### Missing Reentrancy Guard

No `nonReentrant` modifier is present on critical functions:
- `unstakeAndRedeem()`
- `redeem()`
- `unstakeFor()`

---

## Execution Flow

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

**Expected Output:**
```
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

## Timeline

| Step | Action | Result |
|------|--------|--------|
| 1 | Initial analysis | Identified CEI violation in `unstakeFor` |
| 2 | Storage slot discovery | Found Staker slot 2 & 4, LP Token slot 51 |
| 3 | Phase 1 exploit | Drained staked LP tokens (~1.149 ETH) |
| 4 | Phase 2 exploit | Drained non-staked LP tokens (~1.349 ETH) |
| 5 | Validation | Pool drained to 1 wei, ~2.498 ETH |
**Date:** 2026-01-16
**Chain:** Ethereum Mainnet Fork
**Tools:** Foundry, Cast
