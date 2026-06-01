// ===== SECURITY SUMMARY =====
// nonReentrant 保护: 1/4 函数已加锁
// [SAFE] nonReentrant 覆盖所有风险函数，无绕过路径
// =============================


// Contract prelude

contract FixedEtherVault is ReentrancyGuard {
    mapping (address => uint256) private userBalances;

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
        userBalances[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Failed to send Ether");
    }