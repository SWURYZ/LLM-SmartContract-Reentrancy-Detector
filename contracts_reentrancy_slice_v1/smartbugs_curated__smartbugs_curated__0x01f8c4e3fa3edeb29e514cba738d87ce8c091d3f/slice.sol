// ===== SECURITY SUMMARY =====
// [BYPASS-RISK] 无 nonReentrant 保护的调用函数: PERSONAL_BANK.Collect
//   攻击者可回调这些未加锁函数实现跨函数重入
// =============================


// Contract prelude

contract PERSONAL_BANK
{
    mapping (address=>uint256) public balances;
    uint public MinSum = 1 ether;
    LogFile Log = LogFile(0x0486cF65A2F2F3A392CBEa398AFB7F5f0B72FF46);
    bool intitalized;

// [reentrancy-call] Collect

    function Collect(uint _am)
    public
    payable
    {
        if(balances[msg.sender]>=MinSum && balances[msg.sender]>=_am)
        {
            if(msg.sender.call.value(_am)())
            {
                balances[msg.sender]-=_am;
                Log.AddMessage(msg.sender,_am,"Collect");
            }
        }
    }

// [context] Deposit

    function Deposit()
    public
    payable
    {
        balances[msg.sender]+= msg.value;
        Log.AddMessage(msg.sender,msg.value,"Put");
    }

// [context] SetLogFile

    function SetLogFile(address _log)
    public
    {
        if(intitalized)revert();
        Log = LogFile(_log);
    }

// [context] SetMinSum

    function SetMinSum(uint _val)
    public
    {
        if(intitalized)revert();
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
        Deposit();
    }