// ===== SECURITY SUMMARY =====
// nonReentrant 保护: 1/5 函数已加锁
// [SAFE] nonReentrant 覆盖所有风险函数，无绕过路径
// =============================


// Contract prelude

contract FixedAirdrop is ReentrancyGuard {
    mapping (address => uint256) private userBalances;
    mapping (address => bool) private receivedAirdrops;
    uint256 public immutable airdropAmount;

// [guard] nonReentrant 修饰符（重入保护锁）：在执行函数体之前设置 locked=true，阻止回调重入

modifier noReentrant() {
        require(!locked, "No re-entrancy");
        locked = true;
        _;
        locked = false;
    }

// [context] _isContract

    function _isContract(address _account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(_account)
        }
        return size > 0;
    }

// Contract prelude

abstract contract ReentrancyGuard {
    bool internal locked;