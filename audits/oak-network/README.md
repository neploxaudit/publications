# Detailed Results

## Incompatible function signatures in `PaymentTreasuryAdapter`

### Description

The [`PaymentTreasuryAdapter`](https://github.com/oak-network/safe-multisig-helper-contracts/blob/main/contracts/PaymentTreasuryAdapter.sol) uses outdated function signatures that are incompatible with the current [`BasePaymentTreasury`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/utils/BasePaymentTreasury.sol) implementation, causing all adapter calls to fail.

The [`createPayment()`](https://github.com/oak-network/safe-multisig-helper-contracts/blob/main/contracts/PaymentTreasuryAdapter.sol#L7-L29) function in the adapter encodes only 5 parameters:

```solidity
bytes memory data = abi.encodeWithSignature(
    "createPayment(bytes32,bytes32,bytes32,uint256,uint256)",
    paymentId,
    buyerId,
    itemId,
    amount,
    expiration
);
```

However, the actual treasury function requires 8 parameters including `paymentToken`, `lineItems[]`, and `externalFees[]`:

```solidity
function createPayment(
    bytes32 paymentId,
    bytes32 buyerId,
    bytes32 itemId,
    address paymentToken, // Missing in adapter
    uint256 amount,
    uint256 expiration,
    ICampaignPaymentTreasury.LineItem[] calldata lineItems,
    // Missing in adapter
    ICampaignPaymentTreasury.ExternalFees[] calldata externalFees
    // Missing in adapter
) public override virtual onlyPlatformAdmin(PLATFORM_HASH)
```

Similarly, [`confirmPayment()`](https://github.com/oak-network/safe-multisig-helper-contracts/blob/main/contracts/PaymentTreasuryAdapter.sol#L47-L61) is missing the `buyerAddress` parameter, and [`confirmPaymentBatch()`](https://github.com/oak-network/safe-multisig-helper-contracts/blob/main/contracts/PaymentTreasuryAdapter.sol#L63-L77) is missing the `buyerAddresses[]` array. When these adapter functions are called, the treasury contract receives incorrectly encoded calldata, causing function selector mismatch and immediate reversion with `CallFailed()`.

### Recommendations

Update function signatures in [`PaymentTreasuryAdapter.sol`](https://github.com/oak-network/safe-multisig-helper-contracts/blob/main/contracts/PaymentTreasuryAdapter.sol):

1. [`createPayment()`](https://github.com/oak-network/safe-multisig-helper-contracts/blob/main/contracts/PaymentTreasuryAdapter.sol#L7-L29) - Add missing parameters:

```solidity
// Add after itemId parameter:
address paymentToken,

// Add after expiration parameter:
IPaymentTreasury.LineItem[] calldata lineItems,
IPaymentTreasury.ExternalFees[] calldata externalFees

// Update abi.encodeWithSignature (line 17-23):
bytes memory data = abi.encodeWithSignature(
    "createPayment(bytes32,bytes32,bytes32,address,uint256,uint256,(bytes32,uint256)[],(address,uint256)[])",
    paymentId, buyerId, itemId, paymentToken, amount, expiration, lineItems, externalFees
);
```

2. [`confirmPayment()`](https://github.com/oak-network/safe-multisig-helper-contracts/blob/main/contracts/PaymentTreasuryAdapter.sol#L47-L61) - Add `buyerAddress` parameter:

```solidity
// Add after paymentId parameter:
address buyerAddress

// Update abi.encodeWithSignature (line 53-55):
bytes memory data = abi.encodeWithSignature(
    "confirmPayment(bytes32,address)",
    paymentId, buyerAddress
);
```

3. [`confirmPaymentBatch()`](https://github.com/oak-network/safe-multisig-helper-contracts/blob/main/contracts/PaymentTreasuryAdapter.sol#L63-L77) - Add `buyerAddresses` array:

```solidity
// Add after paymentIds parameter:
address[] calldata buyerAddresses

// Update abi.encodeWithSignature (line 69-71):
bytes memory data = abi.encodeWithSignature(
    "confirmPaymentBatch(bytes32[],address[])",
    paymentIds, buyerAddresses
);
```

## Blocking `createPayment` and other payments via front-running `processCryptoPayment`

`d3f37b0b045d37dd71cafe3e5f0003707a9e145d`

### Description

All payment-related functions (important ones are [`createPayment`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/utils/BasePaymentTreasury.sol#L520), [`createPaymentBatch`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/utils/BasePaymentTreasury.sol#L600), [`processCryptoPayment`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/utils/BasePaymentTreasury.sol#L717)) accept a user-controlled `paymentId` parameter that is validated to be unique. For external payments, this value comes from payment providers such as Stripe. The onchain `processCryptoPayment`, however, also uses the same `paymentId` system, which allows attackers to front-run legitimate on- and off-chain transactions and block them by using the same payment ID.

```solidity
// All these functions check payment ID uniqueness:
function createPayment(bytes32 paymentId, ...) { ... }
function createPaymentBatch(bytes32 calldata []paymentIds, ...) { ... }
function processCryptoPayment(bytes32 paymentId, ...) { ... }

// Common check in all functions:
if(s_payment[paymentId].buyerId != ZERO_BYTES || s_payment[paymentId].buyerAddress != address(0)){
  revert PaymentTreasuryPaymentAlreadyExist(paymentId); }
```

The `paymentId` is not scoped to `msg.sender`. An attacker can monitor the mempool for any pending payment transaction, extract the `paymentId`, and front-run it:

- Front-run `createPayment` with `processCryptoPayment(sameId, ..., 1 wei, ...)`
- Front-run `processCryptoPayment` with another `processCryptoPayment(sameId, ..., 1 wei, ...)`

When the legitimate transaction executes, it reverts with `PaymentTreasuryPaymentAlreadyExist`, effectively blocking all real payments to any campaign.

This vulnerability is particularly severe for Stripe integration. An attacker can monitor the platform admin's `createPayment(stripePaymentId, ...)` transactions in the mempool, extract Stripe payment IDs, and front-run them with on-chain `processCryptoPayment(stripePaymentId, ..., 1 wei, ...)`

The payment ID becomes occupied by attacker's 1 wei transaction if the front-run attack is successful. When an off-chain payment's migration to the chain via `createPayment` transaction arrives, it will fail because the ID is already taken. This can severly damage the Stripe integration - legitimate off-chain payments cannot be recorded on-chain, breaking other off-chain systems relying on this and causing potential user fund loss, or at the very least resulting in the need to process refunds for all these failed payment creations.

This is a recurrence of the same vulnerability pattern that previously existed in [`KeepWhatsRaised`](https://github.com/ccprotocol/ccprotocol-contracts-internal/blob/e44a2d34429de9ba8f5fc9a984ee600dada6289b/src/treasuries/KeepWhatsRaised.sol#L627-L664) with `pledgeId` parameters.

### Recommendations

Scope the payment ID to the caller by hashing it with `_msgSender()` in `processCryptoPayment` and other on-chain payment processing functions, and with the zero address for off-chain payment methods (which will allow the platform admin address to change in between these calls without breaking existing payment treasuries), similar to the same fix applied to `KeepWhatsRaised` in [commit 1d6ad87](https://github.com/oak-network/ccprotocol-contracts-internal/commit/1d6ad873f7ca30cd6eab33cfff39022508149dad):

```solidity
function createPayment(bytes32 paymentId, ...) {
    bytes32 internalPaymentId = keccak256(abi.encodePacked(paymentId, ZERO_ADDRESS));
    if(s_payment[internalPaymentId].buyerId != ZERO_BYTES){
        revert PaymentTreasuryPaymentAlreadyExist(internalPaymentId);
    }
    s_payment[internalPaymentId] = PaymentInfo({...});
    ...
}

function processCryptoPayment(bytes32 paymentId, ...) {
    bytes32 internalPaymentId = keccak256(abi.encodePacked(paymentId, _msgSender()));
    ...
}
```

This preserves the external `paymentId` for off-chain tracking with global uniqueness while ensuring uniqueness per caller on-chain.

## Missing Access Control on `withdraw` allows blocking refund mechanism

### Description

The [`withdraw()`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/utils/BasePaymentTreasury.sol#L1607-L1658) function has no access control and can be called by anyone. Combined with [`PaymentTreasury._checkSuccessCondition()`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/treasuries/PaymentTreasury.sol#L169-L177) always returning `true`, this allows any attacker to force withdrawals immediately after payments are received, breaking the entire refund mechanism.

```solidity
function withdraw()
    public // No access control - anyone can call
    virtual
    override
    whenCampaignNotPaused
    whenCampaignNotCancelled
{
    if (!_checkSuccessCondition()) { // Always returns true in PaymentTreasury
        revert PaymentTreasurySuccessConditionNotFulfilled();
    }

    address recipient = INFO.owner();
    // ...
    for (uint256 i = 0; i < acceptedTokens.length; i++) {
        address token = acceptedTokens[i];
        uint256 balance = s_availableConfirmedPerToken[token];
        if (balance > 0) {
            // Transfer funds to owner
            s_availableConfirmedPerToken[token] = 0; // Reset to zero
            IERC20(token).safeTransfer(recipient, withdrawalAmount);
        }
    }
}
```

When `withdraw()` is called, `s_availableConfirmedPerToken[token]` is reset to zero. However, [`claimRefund()`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/utils/BasePaymentTreasury.sol#L1182-L1184) checks this value to determine if refunds are possible:

```solidity
function claimRefund(bytes32 paymentId, address refundAddress) public {
    uint256 availablePaymentAmount = s_availableConfirmedPerToken[paymentToken];

    if (amountToRefund == 0 || availablePaymentAmount < amountToRefund) {
        revert PaymentTreasuryPaymentNotClaimable(paymentId);
        // Will always revert after withdraw
    }
    // ...
}
```

Attack scenario:

1. User makes any payment (via `processCryptoPayment()` or `createPayment()` + `confirmPayment()`)
2. Attacker immediately calls `withdraw()`
3. Campaign owner receives the funds, `s_availableConfirmedPerToken[token]` becomes 0
4. User later tries to claim refund
5. Refund fails with `PaymentTreasuryPaymentNotClaimable` because available balance is 0

This completely breaks the refund mechanism for all payment types. Any attacker can force premature withdrawals after every payment, preventing all future refunds regardless of the campaign owner's intent. The campaign owner has no way to prevent this attack or return funds collected through non-crypto payments (via `createPayment` & `confirmPayment`) except by converting crypto to fiat and manually transferring back to the buyer's bank account.

This creates legal liability issues for the platform if it provides any refund guarantees to users, as the smart contract-based refund mechanism can be completely disabled by any third party.

### Recommendations

Restrict `withdraw()` to be callable only by the campaign owner, or alternatively allow both the campaign owner and platform admin (following the same pattern as [`KeepWhatsRaised`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/treasuries/KeepWhatsRaised.sol#L910-L920)).

Add the `onlyPlatformAdminOrCampaignOwner` modifier (similar to [`KeepWhatsRaised`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/treasuries/KeepWhatsRaised.sol#L910-L920)):

```solidity
// Add this modifier to BasePaymentTreasury
modifier onlyPlatformAdminOrCampaignOwner() {
    if (
        _msgSender() != INFO.getPlatformAdminAddress(PLATFORM_HASH) &&
        _msgSender() != INFO.owner()
    ) {
        revert AccessCheckerUnauthorized();
    }
    _;
}

function withdraw()
    public
    virtual
    override
    onlyPlatformAdminOrCampaignOwner // Apply this modifier
    whenCampaignNotPaused
    whenCampaignNotCancelled
{
    if (!_checkSuccessCondition()) {
        revert PaymentTreasurySuccessConditionNotFulfilled();
    }
    // ...
}
```

This prevents arbitrary third parties from forcing premature withdrawals while allowing authorized parties (owner or platform admin) to control fund withdrawals.

## Campaign owner can block protocol/platform fee & reward collection in `PaymentTreasury` and `TimeConstrainedPaymentTreasury`

### Description

Campaign owners, who we can consider to be low-privileged users in Oak Network, are able to cancel their campaign through [`CampaignInfo._cancelCampaign`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/CampaignInfo.sol#L668) at any point in time, including after launch and before the deadline. Since `BasePaymentTreasury` currently enforces the [`whenCampaignNotPaused`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/utils/BasePaymentTreasury.sol#L315) and [`whenCampaignNotCancelled`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/utils/BasePaymentTreasury.sol#L320) modifiers for all operations, including fee & reward claim methods intended for the platform/protocol ([`disburseFees`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/utils/BasePaymentTreasury.sol#L1454), [`claimNonGoalLineItems`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/utils/BasePaymentTreasury.sol#L1491), [`claimExpiredFunds`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/utils/BasePaymentTreasury.sol#L1522)), they can effectively block the platform they're using to host their campaign, and Oak Network itself, from being compensated according to the configured fee structure.

Besides canceling the `CampaignInfo`, owners are also able to cancel the treasuries themselves in the cases of `PaymentTreasury` and `TimeConstrainedPaymentTreasury`, both of which override `cancelTreasury` like this:

```solidity
function cancelTreasury(bytes32 message) public override {
    if (
        _msgSender() != INFO.getPlatformAdminAddress(PLATFORM_HASH) &&
        _msgSender() != INFO.owner()
    ) {
        revert PaymentTreasuryUnAuthorized();
    }
    _cancel(message);
}
```

Since `PaymentTreasury` enforces the treasury-bound `whenNotPaused` and `whenNotCancelled` modifiers for the [`claimExpiredFunds`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/treasuries/PaymentTreasury.sol#L129) and [`disburseFees`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/treasuries/PaymentTreasury.sol#L136) methods, they are affected through the treasury cancelations additionally to `CampaignInfo` cancelations.

This issue is especially serious due to the fact that [`withdraw`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/utils/BasePaymentTreasury.sol#L1607) calls for the payment treasuries are not time-locked and don't require explicit approval, contrary to withdrawals in the `KeepWhatsRaised` treasury ([`KeepWhatsRaised.withdraw`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/treasuries/KeepWhatsRaised.sol#L919) requires the platform admin to call [`approveWithdrawal`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/treasuries/KeepWhatsRaised.sol#L503)). A malicious campaign owner can wait for enough rewards to accumulate close to the campaign deadline, withdraw them, and cancel the treasury or campaign to lock the remaining protocol and platform fees and rewards.

### Recommendations

It should not be possible to disable protocol and platform fee claiming completely, freezing the funds on the treasury contract forever. The `KeepWhatsRaised` treasury, for example, explicitly allows fund claims despite any present cancelations, blocking only when the treasury or campaign is "paused". Example from [`KeepWhatsRaised.claimFund`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/treasuries/KeepWhatsRaised.sol#L1124):

```solidity
function claimFund()
    external
    onlyPlatformAdmin(PLATFORM_HASH)
    whenCampaignNotPaused
    whenNotPaused
{
    bool isCancelled = s_cancellationTime > 0;
    uint256 cancelLimit = s_cancellationTime + s_config.refundDelay;
    uint256 deadlineLimit = getDeadline() + s_config.withdrawalDelay;

    if ((isCancelled && block.timestamp <= cancelLimit) || (!isCancelled && block.timestamp <= deadlineLimit)) {
        revert KeepWhatsRaisedNotClaimableAdmin();
    }
    ...
}
```

## Missing treasury state validation in `TimeConstrainedPaymentTreasury`

### Description

The [`TimeConstrainedPaymentTreasury`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/treasuries/TimeConstrainedPaymentTreasury.sol) contract uses wrong modifiers on its overridden functions, causing the treasury's own pause and cancel state to never be checked. All functions use `whenCampaignNotPaused` and `whenCampaignNotCancelled` which only validate the campaign's state, not the treasury's state.

For example, in `TimeConstrainedPaymentTreasury`:

```solidity
function createPayment(...) public override whenCampaignNotPaused whenCampaignNotCancelled {
    _checkTimeWithinRange();
    super.createPayment(...); // Already has whenCampaignNotPaused whenCampaignNotCancelled
}
```

The base implementation in `BasePaymentTreasury` already includes these campaign state modifiers:

```solidity
function createPayment(...) public override virtual onlyPlatformAdmin(PLATFORM_HASH) whenCampaignNotPaused whenCampaignNotCancelled {
    // implementation
}
```

This means the treasury's own pause/cancel state is never validated. If the treasury itself is paused or cancelled through [`PausableCancellable`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/utils/PausableCancellable.sol) functions, all payment operations will still execute because only the campaign state is checked, not the treasury state. The same issue affects all overridden functions: `createPaymentBatch()`, `processCryptoPayment()`, `cancelPayment()`, `confirmPayment()`, `confirmPaymentBatch()`, `claimRefund()`, `claimExpiredFunds()`, `disburseFees()`, and `withdraw()`.

In contrast, [`PaymentTreasury`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/treasuries/PaymentTreasury.sol) correctly uses `whenNotPaused` and `whenNotCancelled` (without "Campaign") which check the treasury's own state from [`PausableCancellable`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/utils/PausableCancellable.sol), allowing proper treasury-level pause/cancel functionality.

### Recommendations

Replace `whenCampaignNotPaused` and `whenCampaignNotCancelled` with `whenNotPaused` and `whenNotCancelled` in all overridden functions in `TimeConstrainedPaymentTreasury.sol` to match the pattern used in `PaymentTreasury.sol`:

```solidity
function createPayment(...) public override whenNotPaused whenNotCancelled {
    _checkTimeWithinRange();
    super.createPayment(...);
}
```

This ensures the treasury's own pause/cancel state is properly checked before calling the base implementation, which will then check the campaign's state. Without this fix, pausing or cancelling the treasury contract directly has no effect on payment operations.

## Treasuries missing EIP-2771 Meta-Transaction Support

### Description

None of the treasury contracts ([`BaseTreasury`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/utils/BaseTreasury.sol), [`BasePaymentTreasury`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/utils/BasePaymentTreasury.sol), [`AllOrNothing`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/treasuries/AllOrNothing.sol), [`KeepWhatsRaised`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/treasuries/KeepWhatsRaised.sol), [`PaymentTreasury`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/treasuries/PaymentTreasury.sol), [`TimeConstrainedPaymentTreasury`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/treasuries/TimeConstrainedPaymentTreasury.sol)) implement meta-transaction sender extraction, making the entire safe-multisig-helper-contracts adapter integration non-functional.

All adapter functions in [`PaymentTreasuryAdapter.sol`](https://github.com/oak-network/safe-multisig-helper-contracts/blob/main/contracts/PaymentTreasuryAdapter.sol) correctly append `msg.sender` to calldata following the EIP-2771 pattern:

```solidity
bytes memory dataWithSender = abi.encodePacked(data, msg.sender);
(bool success, ) = treasury.call(dataWithSender);
```

However, `BasePaymentTreasury` never extracts this appended sender. It inherits from [`CampaignAccessChecker`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/utils/CampaignAccessChecker.sol#L13) which uses OpenZeppelin's `Context._msgSender()` that simply returns `msg.sender` (the adapter contract address), not the actual Safe multisig address appended in calldata.

This causes all access control checks to see the `AdapterManager` contract address instead of the Safe multisig address. When the Safe calls `AdapterManager.createPayment()`, which then calls `treasury.createPayment()`, the treasury's `onlyPlatformAdmin` modifier checks `_msgSender()` and gets `address(AdapterManager)` instead of the Safe's address. Since `address(AdapterManager) != platformAdmin`, every transaction reverts with `AccessCheckerUnauthorized()`.

The issue is confirmed by [`MockTreasury.sol`](https://github.com/oak-network/safe-multisig-helper-contracts/blob/main/contracts/mocks/MockTreasury.sol#L35-L43) in the adapter repository, which correctly implements sender extraction for testing. This implementation was never ported to the production treasury contracts, making the entire adapter system unusable for any function with access control modifiers (`onlyPlatformAdmin`, `onlyCampaignOwner`, `onlyProtocolAdmin`).

### Recommendations

Override `_msgSender()` in both `BaseTreasury` and `BasePaymentTreasury` to extract the sender from calldata only when called by a trusted forwarder (adapter contract). Simply extracting from calldata unconditionally would allow any attacker to append a fake address and bypass access control.

Implement EIP-2771 trusted forwarder pattern in both `BaseTreasury` and `BasePaymentTreasury`:

```solidity
// Add to BasePaymentTreasury storage
address public trustedForwarder;

// Set during initialization
function initialize(..., address _trustedForwarder) external initializer {
    // ... existing initialization
    trustedForwarder = _trustedForwarder;
}

// Override _msgSender to extract sender only from trusted forwarder
function _msgSender() internal view override returns (address sender) {
    if (msg.sender == trustedForwarder && msg.data.length >= 20) {
        assembly {
            sender := shr(96, calldataload(sub(calldatasize(), 20)))
        }
    } else {
        sender = msg.sender;
    }
}
```

This ensures that only calls from the designated adapter contract can specify the original sender, while direct calls to the treasury still use `msg.sender` for access control. Without the trusted forwarder check, any attacker could call the treasury directly with an appended admin address and bypass all access restrictions.

## JSON Injection in NFT Metadata

### Description

The [`tokenURI()`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/utils/PledgeNFT.sol#L201-L226) function generates NFT metadata on-chain by concatenating user-controlled strings directly into JSON without escaping special characters. Campaign owners control the NFT name through [`initialize()`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/CampaignInfo.sol#L166-L179) and can set `imageURI` via [`setImageURI()`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/CampaignInfo.sol#L680-L685).

If the NFT name or image URI contains quotes (`"`), backslashes (`\`), or control characters (`\n`, `\r`, `\t`), the resulting JSON becomes invalid or malformed. This breaks NFT metadata on marketplaces.

```solidity
function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
    _requireOwned(tokenId);
    PledgeData memory data = s_pledgeData[tokenId];

    string memory json = string(
        abi.encodePacked(
            '{"name":"', name(), " #", tokenId.toString(), // No escaping
            '","image":"', s_imageURI, // No escaping
            '","attributes":[',
            // ...
            "]}"
        )
    );
    return string(abi.encodePacked("data:application/json;base64,",
                  Base64.encode(bytes(json))));
}
```

Example attack: Setting NFT name to `Pledge NFT","malicious":"injected` produces:

```json
{"name":"Pledge NFT","malicious":"injected #1","image":"..."}
```

The JSON structure is altered, and if more complex injection is used (like unescaped newlines), the JSON becomes completely invalid causing `JSON.parse()` failures in all frontend applications and marketplaces.

Additionally, this on-chain metadata generation is extremely gas-intensive. The function performs multiple `abi.encodePacked()` calls, `toString()` conversions, `toHexString()` operations, and Base64 encoding, consuming approximately 80,000-150,000 gas per call. This is 40-75x more expensive than standard off-chain metadata approaches which cost around 1,500-2,000 gas.

### Recommendations

Switch to off-chain metadata storage with a base URI pattern. Add a `baseTokenURI` storage variable and modify `tokenURI()` to return `baseTokenURI + tokenId + ".json"`. This reduces gas costs by ~98% and allows proper JSON generation on the backend where escaping can be handled correctly.

If on-chain metadata must be preserved, implement JSON string escaping that handles quotes, backslashes, and control characters before concatenation. However, this will add another 20,000-50,000 gas per call.

At minimum, add validation in [`initialize()`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/CampaignInfo.sol#L166-L179) to reject NFT names and image URIs containing quotes, backslashes, or control characters below `0x20`.

## Missing launch buffer validation in launch time update

### Description

The [`updateLaunchTime()`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/CampaignInfo.sol#L535-L550) function allows the campaign owner to set a launch time without enforcing the `CAMPAIGN_LAUNCH_BUFFER` that is required during initial campaign creation. This allows the owner to bypass the buffer period intended to give backers and platforms adequate preparation time.

During campaign creation in [`CampaignInfoFactory.createCampaign()`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/CampaignInfoFactory.sol#L128-L130), the launch buffer is enforced:

```solidity
uint256 campaignLaunchBuffer =
uint256(globalParams.getFromRegistry(
        DataRegistryKeys.CAMPAIGN_LAUNCH_BUFFER));
if (campaignData.launchTime < block.timestamp + campaignLaunchBuffer) {
    revert CampaignInfoFactoryInvalidInput();
}
```

However, `updateLaunchTime()` only checks that the new time is in the future:

```solidity
function updateLaunchTime(uint256 launchTime) external {
    if (launchTime < block.timestamp || getDeadline() <= launchTime) {
        revert CampaignInfoInvalidInput();
    }
    s_campaignData.launchTime = launchTime;
}
```

This allows a campaign owner to update the launch time to be only 1 second in the future, circumventing the buffer requirement. This can be exploited to launch campaigns with insufficient notice, preventing backers from making informed decisions or platforms from properly preparing campaign listings.

### Recommendations

Add the same buffer validation used during campaign creation:

```solidity
function updateLaunchTime(uint256 launchTime) external {
    uint256 campaignLaunchBuffer = uint256(_getGlobalParams().getFromRegistry(DataRegistryKeys.CAMPAIGN_LAUNCH_BUFFER));

    if (launchTime < block.timestamp + campaignLaunchBuffer || getDeadline() <= launchTime) {
        revert CampaignInfoInvalidInput();
    }
    s_campaignData.launchTime = launchTime;
}
```

This ensures consistent enforcement of the launch buffer regardless of whether the time is set during creation or updated later.

## Missing minimum duration validation in deadline update

### Description

The [`updateDeadline()`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/CampaignInfo.sol#L555-L571) function allows the campaign owner to set a deadline without enforcing the `MINIMUM_CAMPAIGN_DURATION` that is required during initial campaign creation. This allows the owner to bypass the minimum duration requirement intended to ensure campaigns run for a reasonable timeframe.

During campaign creation in [`CampaignInfoFactory.createCampaign()`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/CampaignInfoFactory.sol#L131-L133), the minimum duration is enforced:

```solidity
uint256 minimumCampaignDuration = uint256(globalParams.getFromRegistry(DataRegistryKeys.MINIMUM_CAMPAIGN_DURATION));
if (campaignData.deadline < campaignData.launchTime + minimumCampaignDuration) {
    revert CampaignInfoFactoryInvalidInput();
}
```

However, `updateDeadline()` only checks that the deadline is after the launch time:

```solidity
function updateDeadline(uint256 deadline) external {
    if (deadline <= getLaunchTime()) {
        revert CampaignInfoInvalidInput();
    }
    s_campaignData.deadline = deadline;
}
```

This allows a campaign owner to update the deadline to be only 1 second after the launch time, circumventing the minimum duration requirement. This can be exploited to create artificially short campaigns that pressure backers into making rushed decisions without adequate time to evaluate the campaign.

### Recommendations

Add the same minimum duration validation used during campaign creation:

```solidity
function updateDeadline(uint256 deadline) external {
    uint256 minimumCampaignDuration = uint256(_getGlobalParams().getFromRegistry(DataRegistryKeys.MINIMUM_CAMPAIGN_DURATION));

    if (deadline <= getLaunchTime() || deadline < getLaunchTime() + minimumCampaignDuration) {
        revert CampaignInfoInvalidInput();
    }
    s_campaignData.deadline = deadline;
}
```

This ensures consistent enforcement of the minimum campaign duration regardless of whether the deadline is set during creation or updated later.

## Using `encodeWithSignature` Instead of `encodeCall`

`c38f75a11d2ba6f57fff6eecd37dee03d7ea8f11`

### Description

All 24 adapter functions use `abi.encodeWithSignature()` with string literals instead of `abi.encodeCall()`. This provides zero type safety - typos in function names or parameter types compile successfully but fail at runtime.

Issues:

- Typos in function names not caught by compiler
- Wrong parameter types compile fine, call wrong function or fail silently
- No validation that function exists on target contract
- Changes to treasury interfaces don't trigger compile errors in adapters

Affected: All 24 functions in [`PaymentTreasuryAdapter.sol`](https://github.com/oak-network/safe-multisig-helper-contracts/blob/main/contracts/PaymentTreasuryAdapter.sol), [`KeepWhatsRaisedAdapter.sol`](https://github.com/oak-network/safe-multisig-helper-contracts/blob/main/contracts/KeepWhatsRaisedAdapter.sol), [`AllOrNothingAdapter.sol`](https://github.com/oak-network/safe-multisig-helper-contracts/blob/main/contracts/AllOrNothingAdapter.sol).

Current unsafe pattern (`cancelPayment` [example](https://github.com/oak-network/safe-multisig-helper-contracts/blob/main/contracts/PaymentTreasuryAdapter.sol#L37-L40)):

```solidity
bytes memory data = abi.encodeWithSignature(
    "cancelPayment(bytes32)", // String literal - no validation
    paymentId
);
```

Usage of `abi.encodeWithSignature` leads to silent failures, wrong function calls, broken integrations after upgrades.

### Recommendations

Replace all `abi.encodeWithSignature()` calls with `abi.encodeCall()` to get compile-time type safety. The compiler will validate function names, parameter types, and function existence, preventing typos and signature mismatches that only fail at runtime.

Current unsafe code:

```solidity
bytes memory data = abi.encodeWithSignature(
    "cancelPayment(bytes32)",
    paymentId
);
```

Should be replaced with:

```solidity
bytes memory data = abi.encodeCall(
    IPaymentTreasury.cancelPayment,
    (paymentId)
);
```

This change needs to be applied to all 24 adapter functions: 9 functions in [`PaymentTreasuryAdapter.sol`](https://github.com/oak-network/safe-multisig-helper-contracts/blob/main/contracts/PaymentTreasuryAdapter.sol) using `IPaymentTreasury`, 12 functions in [`KeepWhatsRaisedAdapter.sol`](https://github.com/oak-network/safe-multisig-helper-contracts/blob/main/contracts/KeepWhatsRaisedAdapter.sol) using `IKeepWhatsRaised`, and 3 functions in [`AllOrNothingAdapter.sol`](https://github.com/oak-network/safe-multisig-helper-contracts/blob/main/contracts/AllOrNothingAdapter.sol) using `IAllOrNothing`.

With `abi.encodeCall()`, the compiler catches typos, validates parameter types, confirms function existence, and automatically detects when treasury interfaces change. This eliminates an entire class of bugs that currently compile successfully but fail silently at runtime.

## Event order confusion after in NFT Minting

### Description

The [`mintNFTForPledge()`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/utils/PledgeNFT.sol#L110-L139) function emits the [`PledgeNFTMinted`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/utils/PledgeNFT.sol#L136) event after calling [`_safeMint()`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/utils/PledgeNFT.sol#L134). Since `_safeMint()` triggers the `onERC721Received()` callback on the recipient, a reentrancy can occur where the NFT already exists and external calls can be made before the event is emitted.

```solidity
function mintNFTForPledge(
    address backer,
    bytes32 reward,
    address tokenAddress,
    uint256 amount,
    uint256 shippingFee,
    uint256 tipAmount
) public virtual onlyRole(MINTER_ROLE) returns (uint256 tokenId) {
    s_tokenIdCounter.increment();
    tokenId = s_tokenIdCounter.current();

    s_pledgeData[tokenId] = PledgeData({...});

    _safeMint(backer, tokenId);
    // Calls onERC721Received - reentrancy point

    emit PledgeNFTMinted(tokenId, backer, msg.sender, reward);
    // Event after callback

    return tokenId; }
```

This breaks the expected order for off-chain indexers that rely on events to track state changes. During the `onERC721Received()` callback, the receiver can call back into the contract (like `withdraw()` or `disburseFees()` as shown in existing reentrancy tests) and emit other events before `PledgeNFTMinted` is recorded. Indexers will see these events out of order, potentially causing incorrect state tracking.

### Recommendations

Emit the `PledgeNFTMinted` event before calling `_safeMint()` to ensure correct chronological event ordering. The OpenZeppelin ERC721 `Transfer` event will still be emitted during `_safeMint()` after the custom event, which is the expected pattern.

Alternatively, add a `nonReentrant` modifier to `mintNFTForPledge()` to prevent any callbacks from executing during minting, though this adds gas costs and doesn't solve the fundamental event ordering issue.

## Contract reference fetched inside loop

### Description

The [`updateSelectedPlatform()`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/CampaignInfo.sol#L596-L649) function calls `_getGlobalParams()` inside a loop. Each call loads the global params contract address from storage and performs an external call.

```solidity
for (uint256 i = 0; i < platformDataKey.length; i++) {
    isValid = _getGlobalParams().checkIfPlatformDataKeyValid(
    // External call in loop
        platformDataKey[i]
    );
}
```

Each `_getGlobalParams()` call reads from storage and returns a contract reference. While the external call cost dominates, the repeated storage read adds unnecessary overhead. For loops with many platform data keys, this accumulates significantly.

### Recommendations

Cache `_getGlobalParams()` before the loop:

```solidity
IGlobalParams globalParams = _getGlobalParams();
for (uint256 i = 0; i < platformDataKey.length; i++) {
  isValid = globalParams.checkIfPlatformDataKeyValid(platformDataKey[i]);
}
```

This eliminates repeated storage reads and saving gas.

## Precision loss in reward price denormalization

### Description

The [`_denormalizeAmount()`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/utils/BaseTreasury.sol#L146-L161) function rounds down when converting from 18 decimals to token decimals, causing backers to pay slightly less than the intended reward price. This occurs in [`AllOrNothing.pledge()`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/treasuries/AllOrNothing.sol#L459-L461) and [`KeepWhatsRaised._pledge()`](https://github.com/oak-network/ccprotocol-contracts-internal/blob/2.0/rc/src/treasuries/KeepWhatsRaised.sol#L1200-L1201) when processing reward pledges.

```solidity
function _denormalizeAmount(address token, uint256 amount) internal view returns (uint256) {
    uint8 decimals = IERC20Metadata(token).decimals();

    if (decimals < STANDARD_DECIMALS) {
        return amount / (10 ** (STANDARD_DECIMALS - decimals));
        // Rounds down
    }
    // ...
}
```

When reward prices are stored in 18 decimals and converted to tokens with fewer decimals like USDC (6 decimals), the division truncates fractional amounts. For example:

- Reward price: `10.123456789 USDC` = `10123456789000000000` (18 decimals)
- After denormalization: `10123456789000000000 / 10^12` = `10123456` (`10.123456 USDC`)
- Lost amount: `0.000000789 USDC`

The campaign owner loses the fractional difference on every pledge. While the individual loss per transaction is minimal, the fix is straightforward and should be implemented to ensure accurate pricing.

### Recommendations

Round up instead of down to ensure the campaign owner receives at least the intended amount:

```solidity
function _denormalizeAmount(address token, uint256 amount) internal view returns (uint256) {
    uint8 decimals = IERC20Metadata(token).decimals();

    if (decimals < STANDARD_DECIMALS) {
        uint256 divisor = 10 ** (STANDARD_DECIMALS - decimals);
        return (amount + divisor - 1) / divisor; // Round up
    }
    // ...
}
```

Alternatively, validate during reward creation that prices convert cleanly without remainders when using tokens with fewer decimals.
