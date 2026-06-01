// ===== SECURITY SUMMARY =====
// nonReentrant 保护: 6/9 函数已加锁
// [SAFE] nonReentrant 覆盖所有风险函数，无绕过路径
// =============================


// Contract prelude

contract Vault is ERC20, ReentrancyGuard {
    using SafeERC20 for ERC20;
    ERC20 public baseToken;
    IRouter public router;

// [context] swapAndDeposit

    function swapAndDeposit(uint256 _amount, ERC20 _srcToken, uint256 amountOutMin) external nonReentrant {
        uint256 beforeTransfer = baseToken.balanceOf(address(this));
        _srcToken.safeTransferFrom(msg.sender, address(this), _amount);
        address[] memory path = new address[](2);
        path[0] = address(_srcToken);
        path[1] = address(baseToken);
        _srcToken.approve(address(router), _amount);
        router.swapExactTokensForTokens(_amount, amountOutMin, path, address(this), block.timestamp);
        _srcToken.approve(address(router), 0);
        uint256 baseTokenAmount = baseToken.balanceOf(address(this)) - beforeTransfer;
        uint256 share = baseTokenAmount * totalSupply() / beforeTransfer;
        _mint(msg.sender, share);
    }

// [context] withdrawAndSwap

    function withdrawAndSwap(uint256 _share, ERC20 _destToken, uint256 amountOutMin) external nonReentrant {
        uint256 amount = shareToAmount(_share);
        address[] memory path = new address[](2);
        path[0] = address(baseToken);
        path[1] = address(_destToken);
        baseToken.approve(address(router), amount);
        router.swapExactTokensForTokens(amount, amountOutMin, path, address(msg.sender), block.timestamp);
        baseToken.approve(address(router), 0);
        _burn(msg.sender, _share);
    }

// [context] deposit

    function deposit(uint256 _amount) external nonReentrant {
        uint256 total = baseToken.balanceOf(address(this));
        uint256 share = total == 0 ? _amount : amountToShare(_amount);
        _mint(msg.sender, share);
        baseToken.safeTransferFrom(msg.sender, address(this), _amount);
    }

// [context] withdraw

    function withdraw(uint256 _share) external nonReentrant {
        uint256 amount = shareToAmount(_share);
        _burn(msg.sender, _share);
        baseToken.safeTransfer(msg.sender, amount);
    }

// Contract prelude

interface IRouter {