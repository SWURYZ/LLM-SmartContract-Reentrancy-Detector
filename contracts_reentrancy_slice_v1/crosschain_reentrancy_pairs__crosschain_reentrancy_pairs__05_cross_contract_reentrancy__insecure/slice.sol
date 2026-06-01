// ===== SECURITY SUMMARY =====
// [BYPASS-RISK] 无 nonReentrant 保护的调用函数: CrossChainInteraction.initiateCrossChainInteraction
//   攻击者可回调这些未加锁函数实现跨函数重入
// =============================


// Contract prelude

contract CrossChainInteraction {
    address public remoteContractAddress;
    event InteractionInitiated(address initiator, uint256 amount);

// [reentrancy-call] initiateCrossChainInteraction

    function initiateCrossChainInteraction(uint256 amount) public payable {
        require(remoteContractAddress != address(0), "Remote contract address not set");
        require(amount > 0, "Invalid amount");
        (bool success, ) = remoteContractAddress.call{value: amount}("");
        require(success, "Cross-chain interaction failed");
        emit InteractionInitiated(msg.sender, amount);
    }