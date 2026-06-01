// ===== SECURITY SUMMARY =====
// [BYPASS-RISK] 无 nonReentrant 保护的调用函数: VulnerableExternalContract10.withdraw
//   攻击者可回调这些未加锁函数实现跨函数重入
// =============================


// Contract prelude

contract VulnerableExternalContract10 {
    mapping(address => uint) public balances;

// [reentrancy-call] withdraw

    function withdraw(uint amount) public {
        uint balance = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] = balance - amount;
    }