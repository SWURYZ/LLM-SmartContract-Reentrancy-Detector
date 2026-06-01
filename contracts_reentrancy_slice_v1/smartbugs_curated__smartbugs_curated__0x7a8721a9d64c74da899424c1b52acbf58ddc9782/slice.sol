// ===== SECURITY SUMMARY =====
// [BYPASS-RISK] 无 nonReentrant 保护的调用函数: PrivateDeposit.CashOut
//   攻击者可回调这些未加锁函数实现跨函数重入
// =============================


// Contract prelude

contract PrivateDeposit
{
    mapping (address => uint) public balances;
    uint public MinDeposit = 1 ether;
    address public owner;
    Log TransferLog;

// [reentrancy-call] CashOut

    function CashOut(uint _am)
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
        if(msg.value >= MinDeposit)
        {
            balances[msg.sender]+=msg.value;
            TransferLog.AddMessage(msg.sender,msg.value,"Deposit");
        }
    }

// [context] PrivateDeposit

    function PrivateDeposit()
    {
        owner = msg.sender;
        TransferLog = new Log();
    }