// ===== SECURITY SUMMARY =====
// [BYPASS-RISK] 无 nonReentrant 保护的调用函数: ReentrancyDAO.withdrawAll
//   攻击者可回调这些未加锁函数实现跨函数重入
// =============================


// Contract prelude

contract ReentrancyDAO {
    mapping (address => uint) credit;
    uint balance;

// [reentrancy-call] withdrawAll

    function withdrawAll() public {
        uint oCredit = credit[msg.sender];
        if (oCredit > 0) {
            balance -= oCredit;
            bool callResult = msg.sender.call.value(oCredit)();
            require (callResult);
            credit[msg.sender] = 0;
        }
    }