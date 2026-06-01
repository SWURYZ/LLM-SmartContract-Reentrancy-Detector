// ===== SECURITY SUMMARY =====
// =============================


// Contract prelude

contract InsecureAirdrop {
    mapping (address => uint256) private userBalances;
    mapping (address => bool) private receivedAirdrops;
    uint256 public immutable airdropAmount;

// [context] _isContract

    function _isContract(address _account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(_account)
        }
        return size > 0;
    }