// ===== SECURITY SUMMARY =====
// [BYPASS-RISK] 无 nonReentrant 保护的调用函数: ETH_VAULT.CashOut
//   攻击者可回调这些未加锁函数实现跨函数重入
// =============================


// Contract prelude

contract ETH_VAULT
{
    mapping (address => uint) public balances;
    Log TransferLog;
    uint public MinDeposit = 1 ether;

// [reentrancy-call] CashOut

    function CashOut(uint _am)
    public
    payable
    {
        if(_am<=balances[msg.sender])
        {
            if(msg.sender.call.value(_am)())
            {
                balances[msg.sender]-=_am;
                TransferLog.AddMessage(msg.sender,_am,"CashOut");
            }
        }
    }

// [context] Deposit

    function Deposit()
    public
    payable
    {
        if(msg.value > MinDeposit)
        {
            balances[msg.sender]+=msg.value;
            TransferLog.AddMessage(msg.sender,msg.value,"Deposit");
        }
    }

// [context] ETH_VAULT

    function ETH_VAULT(address _log)
    public
    {
        TransferLog = Log(_log);
    }