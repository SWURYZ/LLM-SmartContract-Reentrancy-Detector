// ===== SECURITY SUMMARY =====
// [BYPASS-RISK] 无 nonReentrant 保护的调用函数: HumanStandardToken.approveAndCall, LedgerChannel.LCOpenTimeout, LedgerChannel.consensusCloseChannel, LedgerChannel.byzantineCloseChannel
//   攻击者可回调这些未加锁函数实现跨函数重入
// =============================


// Contract prelude

 contract LedgerChannel {
     string public constant NAME = "Ledger Channel";
     string public constant VERSION = "0.0.1";
     uint256 public numChannels = 0;
     event DidLCOpen (
         bytes32 indexed channelId,
         address indexed partyA,
         address indexed partyI,
         uint256 ethBalanceA,
         address token,
         uint256 tokenBalanceA,
         uint256 LCopenTimeout
     );
     event DidLCJoin (
         bytes32 indexed channelId,
         uint256 ethBalanceI,
         uint256 tokenBalanceI
     );
     event DidLCDeposit (
         bytes32 indexed channelId,
         address indexed recipient,
         uint256 deposit,
         bool isToken
     );
     event DidLCUpdateState (
         bytes32 indexed channelId,
         uint256 sequence,
         uint256 numOpenVc,
         uint256 ethBalanceA,
         uint256 tokenBalanceA,
         uint256 ethBalanceI,
         uint256 tokenBalanceI,
         bytes32 vcRoot,
         uint256 updateLCtimeout
     );
     event DidLCClose (
         bytes32 indexed channelId,
         uint256 sequence,
         uint256 ethBalanceA,
         uint256 tokenBalanceA,
         uint256 ethBalanceI,
         uint256 tokenBalanceI
     );
     event DidVCInit (
         bytes32 indexed lcId,
         bytes32 indexed vcId,
         bytes proof,
         uint256 sequence,
         address partyA,
         address partyB,
         uint256 balanceA,
         uint256 balanceB
     );
     event DidVCSettle (
         bytes32 indexed lcId,
         bytes32 indexed vcId,
         uint256 updateSeq,
         uint256 updateBalA,
         uint256 updateBalB,
         address challenger,
         uint256 updateVCtimeout
     );
     event DidVCClose(
         bytes32 indexed lcId,
         bytes32 indexed vcId,
         uint256 balanceA,
         uint256 balanceB
     );
     struct Channel {
         address[2] partyAddresses;
         uint256[4] ethBalances;
         uint256[4] erc20Balances;
         uint256[2] initialDeposit;
         uint256 sequence;
         uint256 confirmTime;
         bytes32 VCrootHash;
         uint256 LCopenTimeout;
         uint256 updateLCtimeout;
         bool isOpen;
         bool isUpdateLCSettling;
         uint256 numOpenVC;
         HumanStandardToken token;
     }
     struct VirtualChannel {
         bool isClose;
         bool isInSettlementState;
         uint256 sequence;
         address challenger;
         uint256 updateVCtimeout;
         address partyA;
         address partyB;
         address partyI;
         uint256[2] ethBalances;
         uint256[2] erc20Balances;
         uint256[2] bond;
         HumanStandardToken token;
     }
     mapping(bytes32 => VirtualChannel) public virtualChannels;
     mapping(bytes32 => Channel) public Channels;

// [reentrancy-call] byzantineCloseChannel

     function byzantineCloseChannel(bytes32 _lcID) public {
         Channel storage channel = Channels[_lcID];
         require(channel.isOpen, "Channel is not open");
         require(channel.isUpdateLCSettling == true);
         require(channel.numOpenVC == 0);
         require(channel.updateLCtimeout < now, "LC timeout over.");
         uint256 totalEthDeposit = channel.initialDeposit[0] + channel.ethBalances[2] + channel.ethBalances[3];
         uint256 totalTokenDeposit = channel.initialDeposit[1] + channel.erc20Balances[2] + channel.erc20Balances[3];
         uint256 possibleTotalEthBeforeDeposit = channel.ethBalances[0] + channel.ethBalances[1];
         uint256 possibleTotalTokenBeforeDeposit = channel.erc20Balances[0] + channel.erc20Balances[1];
         if(possibleTotalEthBeforeDeposit < totalEthDeposit) {
             channel.ethBalances[0]+=channel.ethBalances[2];
             channel.ethBalances[1]+=channel.ethBalances[3];
         } else {
             require(possibleTotalEthBeforeDeposit == totalEthDeposit);
         }
         if(possibleTotalTokenBeforeDeposit < totalTokenDeposit) {
             channel.erc20Balances[0]+=channel.erc20Balances[2];
             channel.erc20Balances[1]+=channel.erc20Balances[3];
         } else {
             require(possibleTotalTokenBeforeDeposit == totalTokenDeposit);
         }
         uint256 ethbalanceA = channel.ethBalances[0];
         uint256 ethbalanceI = channel.ethBalances[1];
         uint256 tokenbalanceA = channel.erc20Balances[0];
         uint256 tokenbalanceI = channel.erc20Balances[1];
         channel.ethBalances[0] = 0;
         channel.ethBalances[1] = 0;
         channel.erc20Balances[0] = 0;
         channel.erc20Balances[1] = 0;
         if(ethbalanceA != 0 || ethbalanceI != 0) {
             channel.partyAddresses[0].transfer(ethbalanceA);
             channel.partyAddresses[1].transfer(ethbalanceI);
         }
         if(tokenbalanceA != 0 || tokenbalanceI != 0) {
             require(
                 channel.token.transfer(channel.partyAddresses[0], tokenbalanceA),
                 "byzantineCloseChannel: token transfer failure"
             );
             require(
                 channel.token.transfer(channel.partyAddresses[1], tokenbalanceI),
                 "byzantineCloseChannel: token transfer failure"
             );
         }
         channel.isOpen = false;
         numChannels--;
         emit DidLCClose(_lcID, channel.sequence, ethbalanceA, ethbalanceI, tokenbalanceA, tokenbalanceI);
     }

// [reentrancy-call] consensusCloseChannel

     function consensusCloseChannel(
         bytes32 _lcID,
         uint256 _sequence,
         uint256[4] _balances,
         string _sigA,
         string _sigI
     )
         public
     {
         require(Channels[_lcID].isOpen == true);
         uint256 totalEthDeposit = Channels[_lcID].initialDeposit[0] + Channels[_lcID].ethBalances[2] + Channels[_lcID].ethBalances[3];
         uint256 totalTokenDeposit = Channels[_lcID].initialDeposit[1] + Channels[_lcID].erc20Balances[2] + Channels[_lcID].erc20Balances[3];
         require(totalEthDeposit == _balances[0] + _balances[1]);
         require(totalTokenDeposit == _balances[2] + _balances[3]);
         bytes32 _state = keccak256(
             abi.encodePacked(
                 _lcID,
                 true,
                 _sequence,
                 uint256(0),
                 bytes32(0x0),
                 Channels[_lcID].partyAddresses[0],
                 Channels[_lcID].partyAddresses[1],
                 _balances[0],
                 _balances[1],
                 _balances[2],
                 _balances[3]
             )
         );
         require(Channels[_lcID].partyAddresses[0] == ECTools.recoverSigner(_state, _sigA));
         require(Channels[_lcID].partyAddresses[1] == ECTools.recoverSigner(_state, _sigI));
         Channels[_lcID].isOpen = false;
         if(_balances[0] != 0 || _balances[1] != 0) {
             Channels[_lcID].partyAddresses[0].transfer(_balances[0]);
             Channels[_lcID].partyAddresses[1].transfer(_balances[1]);
         }
         if(_balances[2] != 0 || _balances[3] != 0) {
             require(Channels[_lcID].token.transfer(Channels[_lcID].partyAddresses[0], _balances[2]),"happyCloseChannel: token transfer failure");
             require(Channels[_lcID].token.transfer(Channels[_lcID].partyAddresses[1], _balances[3]),"happyCloseChannel: token transfer failure");
         }
         numChannels--;
         emit DidLCClose(_lcID, _sequence, _balances[0], _balances[1], _balances[2], _balances[3]);
     }

// [reentrancy-call] LCOpenTimeout

     function LCOpenTimeout(bytes32 _lcID) public {
         require(msg.sender == Channels[_lcID].partyAddresses[0] && Channels[_lcID].isOpen == false);
         require(now > Channels[_lcID].LCopenTimeout);
         if(Channels[_lcID].initialDeposit[0] != 0) {
             Channels[_lcID].partyAddresses[0].transfer(Channels[_lcID].ethBalances[0]);
         }
         if(Channels[_lcID].initialDeposit[1] != 0) {
             require(Channels[_lcID].token.transfer(Channels[_lcID].partyAddresses[0], Channels[_lcID].erc20Balances[0]),"CreateChannel: token transfer failure");
         }
         emit DidLCClose(_lcID, 0, Channels[_lcID].ethBalances[0], Channels[_lcID].erc20Balances[0], 0, 0);
         delete Channels[_lcID];
     }