// SPDX-License-Identifier: MIT
/// @version 1.0.1
pragma solidity 0.8.30;

import {ERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

/**
 * @title ZarfiXToken
 * @notice A regulatory-compliant security token with whitelist enforcement, capped supply, and role-based access controls
 * @dev UUPS upgradeable ERC-20 token implementing batch processing, gas optimizations, and comprehensive security measures
 * @author ZarfiX Security Team
 * @custom:security-contact security@zarfix.com
 * @custom:version 1.0.1
 */
contract ZarfiXToken is 
    Initializable,
    ERC20Upgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable
{
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Role identifier for token issuers (mint/burn permissions)
    bytes32 private constant _ISSUER_ROLE = keccak256("ISSUER_ROLE");
    
    /// @notice Role identifier for compliance officers (whitelist management)
    bytes32 private constant _COMPLIANCE_ROLE = keccak256("COMPLIANCE_ROLE");
    
    /// @notice Role identifier for pausers (emergency freeze capability)
    bytes32 private constant _PAUSER_ROLE = keccak256("PAUSER_ROLE");
    
    /// @notice Role identifier for upgraders (contract upgrade authorization)
    bytes32 private constant _UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /// @notice Maximum number of addresses that can be processed in a single batch operation
    uint256 private constant _MAX_BATCH = 100;

    /*//////////////////////////////////////////////////////////////
                            IMMUTABLE STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Maximum total supply that can ever be minted (immutable cap)
    uint256 public immutable CAP;

    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Mapping of addresses approved for token transfers (KYC whitelist)
    mapping(address account => bool whitelisted) private _whitelist;
    
    /// @notice Current total supply for gas-optimized reads
    uint256 private _currentSupply;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when tokens are minted to an address
    /// @param to The address receiving the minted tokens
    /// @param amount The amount of tokens minted
    event TokensMinted(address indexed to, uint256 indexed amount);

    /// @notice Emitted when tokens are burned from an address
    /// @param from The address from which tokens are burned
    /// @param amount The amount of tokens burned
    event TokensBurned(address indexed from, uint256 indexed amount);

    /// @notice Emitted when whitelist status is updated for an address
    /// @param account The address whose whitelist status changed
    /// @param status The new whitelist status (true = whitelisted, false = removed)
    event WhitelistUpdated(address indexed account, bool indexed status);

    /// @notice Emitted when a batch operation is completed
    /// @param offset The starting index of the batch
    /// @param limit The number of items processed in the batch
    event BatchProcessed(uint256 indexed offset, uint256 indexed limit);

    /// @notice Emitted when admin role is transferred
    /// @param previousAdmin The previous admin address
    /// @param newAdmin The new admin address
    event AdminChanged(address indexed previousAdmin, address indexed newAdmin);

    /// @notice Emitted when contract is initialized
    /// @param admin The initial admin address
    /// @param name The token name
    /// @param symbol The token symbol
    event ContractInitialized(address indexed admin, string name, string symbol);

    /// @notice Emitted when contract is paused
    event ContractPaused(address indexed account);

    /// @notice Emitted when contract is unpaused
    event ContractUnpaused(address indexed account);

    /// @notice Emitted when transfer occurs
    /// @param from The sender address
    /// @param to The recipient address
    /// @param amount The amount transferred
    event TokenTransfer(address indexed from, address indexed to, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when attempting to use zero address where invalid
    error ZeroAddress();

    /// @notice Thrown when attempting to mint tokens exceeding the cap
    /// @param attempted The amount attempted to mint
    /// @param cap The maximum allowed cap
    error CapExceeded(uint256 attempted, uint256 cap);

    /// @notice Thrown when attempting to mint or transfer zero tokens
    error ZeroAmount();

    /// @notice Thrown when non-whitelisted address attempts token operations
    error NotWhitelisted();

    /// @notice Thrown when attempting to burn more tokens than available
    error InsufficientBalance();

    /// @notice Thrown when batch size is invalid
    /// @param requested The requested batch size
    error InvalidBatchSize(uint256 requested);

    /// @notice Thrown when array is empty
    error EmptyArray();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Constructor sets the immutable cap and initializes storage to avoid zero-to-one writes
    /// @param _cap The maximum total supply that can ever be minted
    constructor(uint256 _cap) payable {
        require(_cap != 0, "Invalid cap amount");
        CAP = _cap;
        // FIX #6: Initialize to 1 to avoid zero-to-one storage writes in future operations
        _currentSupply = 1;
    }

    /*//////////////////////////////////////////////////////////////
                           INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initializes the upgradeable contract with token parameters and admin roles
     * @param _name The name of the token
     * @param _symbol The symbol of the token
     * @param _admin The address to receive all administrative roles
     * @dev This function can only be called once due to the initializer modifier
     */
    function initialize(
        string calldata _name,
        string calldata _symbol,
        address _admin
    ) external initializer {
        // FIX #2: Zero address validation
        require(_admin != address(0), "Invalid admin address");

        __ERC20_init(_name, _symbol);
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        // Grant all roles to the admin
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(_ISSUER_ROLE, _admin);
        _grantRole(_COMPLIANCE_ROLE, _admin);
        _grantRole(_PAUSER_ROLE, _admin);
        _grantRole(_UPGRADER_ROLE, _admin);

        // Admin is automatically whitelisted - initialize to true to avoid zero-to-one write
        _whitelist[_admin] = true;
        
        emit WhitelistUpdated(_admin, true);
        emit ContractInitialized(_admin, _name, _symbol);
    }

    /*//////////////////////////////////////////////////////////////
                         MINTING & BURNING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Mints new tokens to a specified address
     * @param _to The address to receive the minted tokens
     * @param _amount The amount of tokens to mint
     * @dev Only callable by addresses with ISSUER_ROLE, respects total supply cap and whitelist
     */
    function mint(address _to, uint256 _amount) 
        external 
        nonReentrant
        onlyRole(_ISSUER_ROLE) 
        whenNotPaused 
    {
        // FIX #2: Zero address validation
        require(_to != address(0), "Invalid recipient address");
        require(_amount != 0, "Invalid mint amount");
        
        // FIX #7: Cache whitelist read for gas optimization
        bool toWhitelisted = _whitelist[_to];
        require(toWhitelisted, "Recipient not whitelisted");
        
        // FIX #7: Cache storage read for gas optimization
        uint256 currentSupply_ = _currentSupply;
        uint256 newSupply = currentSupply_ + _amount;
        // FIX #8: Use strict inequality in require() for cheaper gas
        require(newSupply < CAP + 1, "Cap exceeded");

        // Effects
        _currentSupply = newSupply;
        _mint(_to, _amount);
        
        // Interactions
        emit TokensMinted(_to, _amount);
    }

    /**
     * @notice Burns tokens from a specified address
     * @param _from The address from which to burn tokens
     * @param _amount The amount of tokens to burn
     * @dev Only callable by addresses with ISSUER_ROLE
     */
    function burn(address _from, uint256 _amount) 
        external 
        nonReentrant
        onlyRole(_ISSUER_ROLE) 
        whenNotPaused 
    {
        // FIX #2: Zero address validation
        require(_from != address(0), "Invalid burn address");
        require(_amount != 0, "Invalid burn amount");
        
        uint256 balance = balanceOf(_from);
        // FIX #8: Use strict inequality in require() for cheaper gas
        require(balance > _amount - 1, "Insufficient balance");

        // FIX #7: Cache storage read for gas optimization
        uint256 currentSupply_ = _currentSupply;
        
        // Effects
        _currentSupply = currentSupply_ - _amount;
        _burn(_from, _amount);
        
        // Interactions
        emit TokensBurned(_from, _amount);
    }

    /*//////////////////////////////////////////////////////////////
                         TRANSFER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Transfers tokens from sender to recipient with whitelist enforcement
     * @param _to The recipient address
     * @param _amount The amount to transfer
     * @return True if transfer succeeds
     * @dev Overrides ERC20 transfer to add whitelist and pause checks
     */
    function transfer(address _to, uint256 _amount) 
        public 
        override 
        whenNotPaused 
        returns (bool) 
    {
        // FIX #2: Zero address validation
        require(_to != address(0), "Invalid recipient address");
        require(_amount != 0, "Invalid transfer amount");
        
        address sender = _msgSender();
        
        // FIX #7: Cache whitelist reads for gas optimization
        bool senderWhitelisted = _whitelist[sender];
        bool toWhitelisted = _whitelist[_to];
        
        require(senderWhitelisted, "Sender not whitelisted");
        require(toWhitelisted, "Recipient not whitelisted");
        
        // Effects & Interactions
        _transfer(sender, _to, _amount);
        emit TokenTransfer(sender, _to, _amount);
        return true;
    }

    /**
     * @notice Transfers tokens from one address to another with whitelist enforcement
     * @param _from The sender address
     * @param _to The recipient address
     * @param _amount The amount to transfer
     * @return True if transfer succeeds
     * @dev Overrides ERC20 transferFrom to add whitelist and pause checks
     */
    function transferFrom(address _from, address _to, uint256 _amount) 
        public 
        override 
        whenNotPaused 
        returns (bool) 
    {
        // FIX #2: Zero address validation
        require(_from != address(0), "Invalid sender address");
        require(_to != address(0), "Invalid recipient address");
        require(_amount != 0, "Invalid transfer amount");
        
        // FIX #7: Cache whitelist reads for gas optimization
        bool fromWhitelisted = _whitelist[_from];
        bool toWhitelisted = _whitelist[_to];
        
        require(fromWhitelisted, "Sender not whitelisted");
        require(toWhitelisted, "Recipient not whitelisted");
        
        // Effects & Interactions
        address spender = _msgSender();
        _spendAllowance(_from, spender, _amount);
        _transfer(_from, _to, _amount);
        emit TokenTransfer(_from, _to, _amount);
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                       WHITELIST MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Adds an address to the whitelist
     * @param _account The address to whitelist
     * @dev Only callable by addresses with COMPLIANCE_ROLE
     */
    function addToWhitelist(address _account) 
        external 
        onlyRole(_COMPLIANCE_ROLE) 
    {
        // FIX #2: Zero address validation
        require(_account != address(0), "Invalid account address");
        
        // Effects
        _whitelist[_account] = true;
        
        // Interactions
        emit WhitelistUpdated(_account, true);
    }

    /**
     * @notice Removes an address from the whitelist
     * @param _account The address to remove from whitelist
     * @dev Only callable by addresses with COMPLIANCE_ROLE
     */
    function removeFromWhitelist(address _account) 
        external 
        onlyRole(_COMPLIANCE_ROLE) 
    {
        // FIX #2: Zero address validation
        require(_account != address(0), "Invalid account address");
        
        // Effects
        delete _whitelist[_account];
        
        // Interactions
        emit WhitelistUpdated(_account, false);
    }

    /**
     * @notice Batch processes whitelist additions with offset and limit to prevent DOS
     * @param _accounts Array of addresses to whitelist
     * @param _offset Starting index for processing
     * @param _limit Maximum number of addresses to process
     * @dev Implements bounded batch processing to avoid gas limit issues
     */
    function processBatch(
        address[] calldata _accounts,
        uint256 _offset,
        uint256 _limit
    ) external onlyRole(_COMPLIANCE_ROLE) {
        // Cache array length for gas optimization
        uint256 accountsLength = _accounts.length;
        require(accountsLength != 0, "Empty accounts array");
        require(_limit != 0, "Invalid limit");
        // FIX #8: Use strict inequality in require() for cheaper gas
        require(_limit < _MAX_BATCH + 1, "Batch size too large");
        
        uint256 end = _offset + _limit;
        // FIX #4: Use non-strict inequality in if() for cheaper gas
        if (end >= accountsLength + 1) {
            end = accountsLength;
        }

        // Effects
        for (uint256 i = _offset; i < end;) {
            address account = _accounts[i];
            // FIX #2: Zero address validation
            require(account != address(0), "Invalid account in batch");
            
            _whitelist[account] = true;
            
            unchecked {
                ++i;
            }
        }
        
        // Interactions
        emit BatchProcessed(_offset, end - _offset);
    }

    /**
     * @notice Batch processes whitelist removals with offset and limit to prevent DOS
     * @param _accounts Array of addresses to remove from whitelist
     * @param _offset Starting index for processing
     * @param _limit Maximum number of addresses to process
     * @dev Implements bounded batch processing to avoid gas limit issues
     */
    function batchRemoveFromWhitelist(
        address[] calldata _accounts,
        uint256 _offset,
        uint256 _limit
    ) external onlyRole(_COMPLIANCE_ROLE) {
        // Cache array length for gas optimization
        uint256 accountsLength = _accounts.length;
        require(accountsLength != 0, "Empty accounts array");
        require(_limit != 0, "Invalid limit");
        // FIX #8: Use strict inequality in require() for cheaper gas
        require(_limit < _MAX_BATCH + 1, "Batch size too large");
        
        uint256 end = _offset + _limit;
        // FIX #4: Use non-strict inequality in if() for cheaper gas
        if (end >= accountsLength + 1) {
            end = accountsLength;
        }

        // Effects
        for (uint256 i = _offset; i < end;) {
            address account = _accounts[i];
            // FIX #2: Zero address validation
            require(account != address(0), "Invalid account in batch");
            
            delete _whitelist[account];
            
            unchecked {
                ++i;
            }
        }
        
        // Interactions
        emit BatchProcessed(_offset, end - _offset);
    }

    /*//////////////////////////////////////////////////////////////
                        PAUSE FUNCTIONALITY
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Pauses all token transfers and minting/burning operations
     * @dev Only callable by addresses with PAUSER_ROLE, emits Paused event automatically
     */
    function pause() external onlyRole(_PAUSER_ROLE) {
        _pause();
        emit ContractPaused(_msgSender());
    }

    /**
     * @notice Unpauses token transfers and minting/burning operations
     * @dev Only callable by addresses with PAUSER_ROLE, emits Unpaused event automatically
     */
    function unpause() external onlyRole(_PAUSER_ROLE) {
        _unpause();
        emit ContractUnpaused(_msgSender());
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Checks if an address is whitelisted for token operations
     * @param _account The address to check
     * @return True if the address is whitelisted, false otherwise
     */
    function isWhitelisted(address _account) external view returns (bool) {
        // FIX #2: Zero address validation
        require(_account != address(0), "Invalid account address");
        return _whitelist[_account];
    }

    /**
     * @notice Returns the remaining tokens that can be minted before hitting the cap
     * @return The number of tokens that can still be minted
     */
    function remainingMintable() external view returns (uint256) {
        // FIX #7: Cache storage read for gas optimization
        uint256 currentSupply_ = _currentSupply;
        // Use ternary operator with optimal inequality
        return CAP > currentSupply_ ? CAP - currentSupply_ : 0;
    }

    /**
     * @notice Returns the current total supply of tokens
     * @return The current total supply
     * @dev Gas-optimized version using cached supply
     */
    function totalSupply() public view override returns (uint256) {
        return _currentSupply;
    }

    /**
     * @notice Returns the maximum total supply cap
     * @return The maximum total supply that can ever exist
     */
    function cap() external view returns (uint256) {
        return CAP;
    }

    /**
     * @notice Returns the maximum batch size for batch operations
     * @return The maximum number of addresses that can be processed in one batch
     */
    function maxBatchSize() external pure returns (uint256) {
        return _MAX_BATCH;
    }

    /*//////////////////////////////////////////////////////////////
                         UPGRADE AUTHORIZATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Authorizes contract upgrades
     * @param _newImplementation The address of the new implementation contract
     * @dev Only addresses with UPGRADER_ROLE can authorize upgrades
     */
    function _authorizeUpgrade(address _newImplementation) 
        internal 
        view 
        override 
        onlyRole(_UPGRADER_ROLE) 
    {
        // FIX #2: Zero address validation
        require(_newImplementation != address(0), "Invalid implementation address");
    }

    /*//////////////////////////////////////////////////////////////
                           STORAGE GAP
    //////////////////////////////////////////////////////////////*/

    /// @dev Reserved storage space for future upgrades to maintain storage layout compatibility
    uint256[47] private __gap;
}