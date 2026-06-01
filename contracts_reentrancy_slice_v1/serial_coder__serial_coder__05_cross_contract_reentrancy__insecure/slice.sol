// ===== SECURITY SUMMARY =====
// nonReentrant 保护: 2/5 函数已加锁
// [SAFE] nonReentrant 覆盖所有风险函数，无绕过路径
// =============================


// Contract prelude

contract InsecureMoonVault is ReentrancyGuard {
    IMoonToken public immutable moonToken;

// [guard] nonReentrant 修饰符（重入保护锁）：在执行函数体之前设置 locked=true，阻止回调重入

modifier noReentrant() {
        require(!locked, "No re-entrancy");
        locked = true;
        _;
        locked = false;
    }

// [reentrancy-call] withdrawAll

    function withdrawAll() external noReentrant {
        uint256 balance = getUserBalance(msg.sender);
        require(balance > 0, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Failed to send Ether");
        success = moonToken.burnAccount(msg.sender);
        require(success, "Failed to burn token");
    }