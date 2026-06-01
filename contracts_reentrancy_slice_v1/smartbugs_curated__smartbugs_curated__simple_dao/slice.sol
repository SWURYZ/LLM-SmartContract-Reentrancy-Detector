// ===== SECURITY SUMMARY =====
// [BYPASS-RISK] 无 nonReentrant 保护的调用函数: SimpleDAO.withdraw
//   攻击者可回调这些未加锁函数实现跨函数重入
// =============================


// Contract prelude

contract SimpleDAO {
  mapping (address => uint) public credit;

// [reentrancy-call] withdraw

  function withdraw(uint amount) {
    if (credit[msg.sender]>= amount) {
      bool res = msg.sender.call.value(amount)();
      credit[msg.sender]-=amount;
    }
  }