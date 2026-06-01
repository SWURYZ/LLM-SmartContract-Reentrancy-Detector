// ===== SECURITY SUMMARY =====
// [BYPASS-RISK] 无 nonReentrant 保护的调用函数: W_WALLET.Collect
//   攻击者可回调这些未加锁函数实现跨函数重入
// =============================


// Contract prelude

contract W_WALLET
{

// [reentrancy-call] Collect

    function Collect(uint _am)
    public
    payable
    {
        var acc = Acc[msg.sender];
        if( acc.balance>=MinSum && acc.balance>=_am && now>acc.unlockTime)
        {
            if(msg.sender.call.value(_am)())
            {
                acc.balance-=_am;
                LogFile.AddMessage(msg.sender,_am,"Collect");
            }
        }
    }

// [context] Put

    function Put(uint _unlockTime)
    public
    payable
    {
        var acc = Acc[msg.sender];
        acc.balance += msg.value;
        acc.unlockTime = _unlockTime>now?_unlockTime:now;
        LogFile.AddMessage(msg.sender,msg.value,"Put");
    }

// [context] function

    function()
    public
    payable
    {
        Put(0);
    }