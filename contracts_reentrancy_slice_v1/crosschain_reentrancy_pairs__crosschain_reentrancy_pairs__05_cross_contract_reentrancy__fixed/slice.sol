// ===== SECURITY SUMMARY =====
// =============================


// Contract prelude

contract CrossChainDataTransferCosmos {
    address public cosmosBridgeAddress;
    event DataTransferred(address indexed fromChain, address indexed toChain, bytes32 indexed id, string data);

// [context] transferData

    function transferData(bytes32 id, string memory newData) public {
        require(bytes(newData).length > 0, "Data should not be empty");
        CosmosBridge(cosmosBridgeAddress).transferDataToCosmos(id, newData);
        emit DataTransferred(address(this), cosmosBridgeAddress, id, newData);
    }

// Contract prelude

interface CosmosBridge {