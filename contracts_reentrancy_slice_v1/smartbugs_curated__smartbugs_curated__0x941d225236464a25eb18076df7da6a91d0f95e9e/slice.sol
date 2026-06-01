// ===== SECURITY SUMMARY =====
// [BYPASS-RISK] 无 nonReentrant 保护的调用函数: ETH_FUND.CashOut
//   攻击者可回调这些未加锁函数实现跨函数重入
// =============================


// Contract prelude

contract ETH_FUND
{
    mapping (address => uint) public balances;
    uint public MinDeposit = 1 ether;
    Log TransferLog;
    uint lastBlock;

// [reentrancy-call] CashOut

    function CashOut(uint _am)
    public
    payable
    {
        if(_am<=balances[msg.sender]&&block.number>lastBlock)
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
            lastBlock = block.number;
        }
    }

// [context] ETH_FUND

    function ETH_FUND(address _log)
    public
    {
        TransferLog = Log(_log);
    }