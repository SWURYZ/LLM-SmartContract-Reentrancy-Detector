// ===== SECURITY SUMMARY =====
// =============================


// Contract prelude

contract CrossChainDataTransferPolkadot {
    address public polkadotBridgeAddress;
    event DataTransferred(address indexed fromChain, address indexed toChain, bytes32 indexed id, string data);

// [context] transferData

    function transferData(bytes32 id, string memory newData) public {
        require(bytes(newData).length > 0, "Data should not be empty");
        Bridge(polkadotBridgeAddress).transferDataToPolkadot(id, newData);
        emit DataTransferred(address(this), polkadotBridgeAddress, id, newData);
    }

// Contract prelude

interface Bridge {