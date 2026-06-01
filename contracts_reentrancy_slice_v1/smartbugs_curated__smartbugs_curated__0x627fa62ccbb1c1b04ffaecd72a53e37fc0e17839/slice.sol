// ===== SECURITY SUMMARY =====
// [BYPASS-RISK] 无 nonReentrant 保护的调用函数: Token.WithdrawToken, TokenBank.WithdrawToHolder
//   攻击者可回调这些未加锁函数实现跨函数重入
// =============================


// Contract prelude

contract TokenBank is Token
{
    uint public MinDeposit;
    mapping (address => uint) public Holders;

// [reentrancy-call] WithdrawToHolder

    function WithdrawToHolder(address _addr, uint _wei)
    public
    onlyOwner
    payable
    {
        if(Holders[_addr]>0)
        {
            if(_addr.call.value(_wei)())
            {
                Holders[_addr]-=_wei;
            }
        }
    }

// [context] WitdrawTokenToHolder

    function WitdrawTokenToHolder(address _to,address _token,uint _amount)
    public
    onlyOwner
    {
        if(Holders[_to]>0)
        {
            Holders[_to]=0;
            WithdrawToken(_token,_amount,_to);
        }
    }

// [context] Deposit

    function Deposit()
    payable
    {
        if(msg.value>MinDeposit)
        {
            Holders[msg.sender]+=msg.value;
        }
    }

// [context] initTokenBank

    function initTokenBank()
    public
    {
        owner = msg.sender;
        MinDeposit = 1 ether;
    }

// [context] function

    function()
    payable
    {
        Deposit();
    }

// Contract prelude

contract Token is Ownable
{
    address owner = msg.sender;

// [reentrancy-call] WithdrawToken

    function WithdrawToken(address token, uint256 amount,address to)
    public
    onlyOwner
    {
        token.call(bytes4(sha3("transfer(address,uint256)")),to,amount);
    }