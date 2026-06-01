// ===== SECURITY SUMMARY =====
// [BYPASS-RISK] 无 nonReentrant 保护的调用函数: Reentrancy_bonus.withdrawReward
//   攻击者可回调这些未加锁函数实现跨函数重入
// =============================


// Contract prelude

contract Reentrancy_bonus{
    mapping (address => uint) private userBalances;
    mapping (address => bool) private claimedBonus;
    mapping (address => uint) private rewardsForA;

// [reentrancy-call] withdrawReward

    function withdrawReward(address recipient) public {
        uint amountToWithdraw = rewardsForA[recipient];
        rewardsForA[recipient] = 0;
        (bool success, ) = recipient.call.value(amountToWithdraw)("");
        require(success);
    }

// [context] getFirstWithdrawalBonus

    function getFirstWithdrawalBonus(address recipient) public {
        require(!claimedBonus[recipient]);
        rewardsForA[recipient] += 100;
        withdrawReward(recipient);
        claimedBonus[recipient] = true;
    }