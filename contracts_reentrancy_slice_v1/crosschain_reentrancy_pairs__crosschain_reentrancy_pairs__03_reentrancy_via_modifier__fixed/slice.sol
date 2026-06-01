// ===== SECURITY SUMMARY =====
// =============================


// Contract prelude

contract CrossChainDataTransfer1 {
    mapping(address => mapping(bytes32 => string)) public transferredData;
    event DataTransferred(address indexed fromChain, address indexed toChain, bytes32 indexed id, string data);

// [context] transferData

    function transferData(address targetChain, bytes32 id, string memory newData) public {
        require(bytes(newData).length > 0, "Data should not be empty");
        require(targetChain != address(0), "Invalid target chain address");
        transferredData[targetChain][id] = newData;
        emit DataTransferred(address(this), targetChain, id, newData);
    }