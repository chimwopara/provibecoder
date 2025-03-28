// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title ProVibeToken
 * @dev ERC20 token for the ProVibeCoder platform
 * This token represents equity in projects and can be distributed to
 * contributors based on their work.
 */
contract ProVibeToken is ERC20, ERC20Burnable, Ownable {
    // Token metadata
    string private _name = "ProVibe Token";
    string private _symbol = "PVT";
    
    // Maximum tokens that can ever be minted (100 million tokens)
    uint256 public constant MAX_SUPPLY = 100000000 * 10**18;
    
    // Current total supply
    uint256 private _totalSupply;
    
    // Platform fee percentage (0.5%)
    uint256 public platformFeePercent = 50; // Out of 10000 (0.5%)
    
    // Address to receive platform fees
    address public feeReceiver;
    
    // Mapping of project IDs to their token information
    mapping(bytes32 => ProjectToken) public projectTokens;
    
    // Structure to hold project token information
    struct ProjectToken {
        bool exists;
        uint256 totalTokens;
        uint256 founderTokens;
        uint256 developerTokens;
        uint256 legalTokens;
        uint256 investorTokens;
        uint256 platformTokens;
        bool initialized;
    }
    
    // Events
    event ProjectTokenCreated(bytes32 indexed projectId, uint256 totalTokens);
    event EquityDistributed(bytes32 indexed projectId, address indexed recipient, uint256 amount, string role);
    
    /**
     * @dev Constructor - initializes the token
     * @param initialOwner The initial owner of the contract
     * @param _feeReceiver The address to receive platform fees
     */
    constructor(address initialOwner, address _feeReceiver) ERC20(_name, _symbol) Ownable(initialOwner) {
        require(_feeReceiver != address(0), "Fee receiver cannot be zero address");
        feeReceiver = _feeReceiver;
    }
    
    /**
     * @dev Creates tokens for a new project
     * @param projectId Unique identifier for the project
     * @param totalTokens Total number of tokens to allocate for this project
     * @param founderPercent Percentage of tokens allocated to the founder (in basis points, 1% = 100)
     * @param developerPercent Percentage of tokens allocated to developers (in basis points)
     * @param legalPercent Percentage of tokens allocated to legal experts (in basis points)
     * @param investorPercent Percentage of tokens allocated to investors (in basis points)
     */
    function createProjectTokens(
        bytes32 projectId,
        uint256 totalTokens,
        uint256 founderPercent,
        uint256 developerPercent,
        uint256 legalPercent,
        uint256 investorPercent
    ) external onlyOwner {
        require(!projectTokens[projectId].exists, "Project tokens already created");
        require(totalTokens > 0, "Total tokens must be greater than 0");
        
        // Check that percentages add up to 10000 (100%)
        uint256 totalPercent = founderPercent + developerPercent + legalPercent + investorPercent;
        require(totalPercent == 10000, "Percentages must add up to 100%");
        
        // Check that minting these tokens won't exceed max supply
        require(_totalSupply + totalTokens <= MAX_SUPPLY, "Would exceed maximum token supply");
        
        // Calculate token amounts for each role
        uint256 founderTokens = (totalTokens * founderPercent) / 10000;
        uint256 developerTokens = (totalTokens * developerPercent) / 10000;
        uint256 legalTokens = (totalTokens * legalPercent) / 10000;
        uint256 investorTokens = (totalTokens * investorPercent) / 10000;
        
        // Calculate platform fee
        uint256 platformTokens = (totalTokens * platformFeePercent) / 10000;
        
        // Store project token info
        projectTokens[projectId] = ProjectToken({
            exists: true,
            totalTokens: totalTokens,
            founderTokens: founderTokens,
            developerTokens: developerTokens,
            legalTokens: legalTokens,
            investorTokens: investorTokens,
            platformTokens: platformTokens,
            initialized: false
        });
        
        // Increase total supply counter
        _totalSupply += totalTokens;
        
        emit ProjectTokenCreated(projectId, totalTokens);
    }
    
    /**
     * @dev Distributes founder equity for a project
     * @param projectId The project identifier
     * @param founder The founder's address
     */
    function distributeFounderEquity(bytes32 projectId, address founder) external onlyOwner {
        ProjectToken storage project = projectTokens[projectId];
        require(project.exists, "Project does not exist");
        require(founder != address(0), "Founder address cannot be zero");
        require(!project.initialized, "Project already initialized");
        
        // Mint tokens to the founder
        _mint(founder, project.founderTokens);
        
        // Mint platform fee tokens
        _mint(feeReceiver, project.platformTokens);
        
        // Mark project as initialized
        project.initialized = true;
        
        emit EquityDistributed(projectId, founder, project.founderTokens, "founder");
        emit EquityDistributed(projectId, feeReceiver, project.platformTokens, "platform");
    }
    
    /**
     * @dev Distributes developer equity for a project
     * @param projectId The project identifier
     * @param developer The developer's address
     * @param amount The amount of tokens to distribute
     */
    function distributeDeveloperEquity(bytes32 projectId, address developer, uint256 amount) external onlyOwner {
        ProjectToken storage project = projectTokens[projectId];
        require(project.exists, "Project does not exist");
        require(project.initialized, "Project not initialized");
        require(developer != address(0), "Developer address cannot be zero");
        require(amount > 0, "Amount must be greater than 0");
        require(amount <= project.developerTokens, "Amount exceeds available developer tokens");
        
        // Reduce available developer tokens
        project.developerTokens -= amount;
        
        // Mint tokens to the developer
        _mint(developer, amount);
        
        emit EquityDistributed(projectId, developer, amount, "developer");
    }
    
    /**
     * @dev Distributes legal expert equity for a project
     * @param projectId The project identifier
     * @param legalExpert The legal expert's address
     * @param amount The amount of tokens to distribute
     */
    function distributeLegalEquity(bytes32 projectId, address legalExpert, uint256 amount) external onlyOwner {
        ProjectToken storage project = projectTokens[projectId];
        require(project.exists, "Project does not exist");
        require(project.initialized, "Project not initialized");
        require(legalExpert != address(0), "Legal expert address cannot be zero");
        require(amount > 0, "Amount must be greater than 0");
        require(amount <= project.legalTokens, "Amount exceeds available legal tokens");
        
        // Reduce available legal tokens
        project.legalTokens -= amount;
        
        // Mint tokens to the legal expert
        _mint(legalExpert, amount);
        
        emit EquityDistributed(projectId, legalExpert, amount, "legal");
    }
    
    /**
     * @dev Distributes investor equity for a project
     * @param projectId The project identifier
     * @param investor The investor's address
     * @param amount The amount of tokens to distribute
     */
    function distributeInvestorEquity(bytes32 projectId, address investor, uint256 amount) external onlyOwner {
        ProjectToken storage project = projectTokens[projectId];
        require(project.exists, "Project does not exist");
        require(project.initialized, "Project not initialized");
        require(investor != address(0), "Investor address cannot be zero");
        require(amount > 0, "Amount must be greater than 0");
        require(amount <= project.investorTokens, "Amount exceeds available investor tokens");
        
        // Reduce available investor tokens
        project.investorTokens -= amount;
        
        // Mint tokens to the investor
        _mint(investor, amount);
        
        emit EquityDistributed(projectId, investor, amount, "investor");
    }
    
    /**
     * @dev Updates the platform fee percentage
     * @param newFeePercent New fee percentage (in basis points, 1% = 100)
     */
    function updatePlatformFee(uint256 newFeePercent) external onlyOwner {
        require(newFeePercent <= 500, "Fee cannot exceed 5%");
        platformFeePercent = newFeePercent;
    }
    
    /**
     * @dev Updates the fee receiver address
     * @param newFeeReceiver New address to receive platform fees
     */
    function updateFeeReceiver(address newFeeReceiver) external onlyOwner {
        require(newFeeReceiver != address(0), "Fee receiver cannot be zero address");
        feeReceiver = newFeeReceiver;
    }
    
    /**
     * @dev Gets the remaining available tokens for a specific role in a project
     * @param projectId The project identifier
     * @param role The role (1=founder, 2=developer, 3=legal, 4=investor)
     * @return The amount of tokens available for the specified role
     */
    function getAvailableTokens(bytes32 projectId, uint8 role) external view returns (uint256) {
        ProjectToken storage project = projectTokens[projectId];
        require(project.exists, "Project does not exist");
        
        if (role == 1) return project.founderTokens;
        if (role == 2) return project.developerTokens;
        if (role == 3) return project.legalTokens;
        if (role == 4) return project.investorTokens;
        
        revert("Invalid role");
    }
    
    /**
     * @dev Returns the current total supply of tokens
     */
    function totalSupply() public view override returns (uint256) {
        return _totalSupply;
    }
}