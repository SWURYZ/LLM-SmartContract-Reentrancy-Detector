// ===== SECURITY SUMMARY =====
// [BYPASS-RISK] 无 nonReentrant 保护的调用函数: Reentrance.withdraw
//   攻击者可回调这些未加锁函数实现跨函数重入
// =============================


// Contract prelude

contract Reentrance {
  mapping(address => uint) public balances;

// [reentrancy-call] withdraw

  function withdraw(uint _amount) public {
    if(balances[msg.sender] >= _amount) {
      if(msg.sender.call.value(_amount)()) {
        _amount;
      }
      balances[msg.sender] -= _amount;
    }
  }