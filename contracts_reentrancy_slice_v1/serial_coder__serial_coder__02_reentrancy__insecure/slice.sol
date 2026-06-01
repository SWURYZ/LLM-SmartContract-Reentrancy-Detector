// ===== SECURITY SUMMARY =====
// [BYPASS-RISK] 无 nonReentrant 保护的调用函数: InsecureEtherVault.withdrawAll
//   攻击者可回调这些未加锁函数实现跨函数重入
// =============================


// Contract prelude

contract InsecureEtherVault {
    mapping (address => uint256) private userBalances;

// [reentrancy-call] withdrawAll

    function withdrawAll() external {
        uint256 balance = getUserBalance(msg.sender);
        require(balance > 0, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Failed to send Ether");
        userBalances[msg.sender] = 0;
    }