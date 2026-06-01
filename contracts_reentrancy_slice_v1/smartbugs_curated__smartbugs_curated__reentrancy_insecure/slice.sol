// ===== SECURITY SUMMARY =====
// [BYPASS-RISK] 无 nonReentrant 保护的调用函数: Reentrancy_insecure.withdrawBalance
//   攻击者可回调这些未加锁函数实现跨函数重入
// =============================


// Contract prelude

contract Reentrancy_insecure {
    mapping (address => uint) private userBalances;

// [reentrancy-call] withdrawBalance

    function withdrawBalance() public {
        uint amountToWithdraw = userBalances[msg.sender];
        (bool success, ) = msg.sender.call.value(amountToWithdraw)("");
        require(success);
        userBalances[msg.sender] = 0;
    }