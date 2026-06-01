// ===== SECURITY SUMMARY =====
// [BYPASS-RISK] 无 nonReentrant 保护的调用函数: Reentrance.withdrawBalance
//   攻击者可回调这些未加锁函数实现跨函数重入
// =============================


// Contract prelude

 contract Reentrance {
     mapping (address => uint) userBalance;

// [reentrancy-call] withdrawBalance

     function withdrawBalance(){
         if( ! (msg.sender.call.value(userBalance[msg.sender])() ) ){
             throw;
         }
         userBalance[msg.sender] = 0;
     }