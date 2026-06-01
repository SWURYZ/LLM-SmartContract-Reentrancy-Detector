// ===== SECURITY SUMMARY =====
// [BYPASS-RISK] 无 nonReentrant 保护的调用函数: EtherBank.withdrawBalance
//   攻击者可回调这些未加锁函数实现跨函数重入
// =============================


// Contract prelude

contract EtherBank{
    mapping (address => uint) userBalances;

// [reentrancy-call] withdrawBalance

	function withdrawBalance() {
		uint amountToWithdraw = userBalances[msg.sender];
		if (!(msg.sender.call.value(amountToWithdraw)())) { throw; }
		userBalances[msg.sender] = 0;
	}