// ===== SECURITY SUMMARY =====
// [BYPASS-RISK] 无 nonReentrant 保护的调用函数: MONEY_BOX.Collect
//   攻击者可回调这些未加锁函数实现跨函数重入
// =============================


// Contract prelude

contract MONEY_BOX
{
    struct Holder
    {
        uint unlockTime;
        uint balance;
    }
    mapping (address => Holder) public Acc;
    uint public MinSum;
    Log LogFile;
    bool intitalized;

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

    function Put(uint _lockTime)
    public
    payable
    {
        var acc = Acc[msg.sender];
        acc.balance += msg.value;
        if(now+_lockTime>acc.unlockTime)acc.unlockTime=now+_lockTime;
        LogFile.AddMessage(msg.sender,msg.value,"Put");
    }

// [context] SetLogFile

    function SetLogFile(address _log)
    public
    {
        if(intitalized)throw;
        LogFile = Log(_log);
    }

// [context] SetMinSum

    function SetMinSum(uint _val)
    public
    {
        if(intitalized)throw;
        MinSum = _val;
    }

// [context] Initialized

    function Initialized()
    public
    {
        intitalized = true;
    }

// [context] function

    function()
    public
    payable
    {
        Put(0);
    }