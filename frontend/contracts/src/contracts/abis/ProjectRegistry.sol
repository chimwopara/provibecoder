// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./ProVibeToken.sol";

/**
 * @title ProjectRegistry
 * @dev Registry for ProVibeCoder projects with equity management
 * This contract manages project registration and the distribution
 * of equity rewards to contributors
 */
contract ProjectRegistry is Ownable {
    // Reference to the ProVibeToken contract
    ProVibeToken public proVibeToken;
    
    // Structure to hold project information
    struct Project {
        bytes32 id;
        address founder;
        string metadataURI;
        bool exists;
        bool active;
        uint256 createdAt;
        uint256 totalEquity;
        uint256 equityPrice;  // Price per equity unit in ETH (wei)
        mapping(address => Contribution) developerContributions;
        mapping(address => Contribution) legalContributions;
        mapping(address => Investment) investments;
        address[] developers;
        address[] legalExperts;
        address[] investors;
    }
    
    // Structure to hold contribution information
    struct Contribution {
        uint256 equityAmount;
        bool hasContributed;
        bool equityDistributed;
    }
    
    // Structure to hold investment information
    struct Investment {
        uint256 amount;
        uint256 equityAmount;
        bool active;
    }
    
    // Mapping from project ID to Project
    mapping(bytes32 => Project) private projects;
    
    // Array of all project IDs
    bytes32[] private projectIds;
    
    // Default equity distribution (in basis points, 1% = 100)
    uint256 public defaultFounderPercent = 6000;  // 60%
    uint256 public defaultDeveloperPercent = 2500;  // 25%
    uint256 public defaultLegalPercent = 500;  // 5%
    uint256 public defaultInvestorPercent = 1000;  // 10%
    
    // Events
    event ProjectRegistered(bytes32 indexed projectId, address indexed founder, string metadataURI);
    event DeveloperAssigned(bytes32 indexed projectId, address indexed developer, uint256 equityAmount);
    event LegalExpertAssigned(bytes32 indexed projectId, address indexed legalExpert, uint256 equityAmount);
    event InvestmentReceived(bytes32 indexed projectId, address indexed investor, uint256 amount, uint256 equityAmount);
    event EquityDistributed(bytes32 indexed projectId, address indexed recipient, uint256 equityAmount);
    event ProjectStatusChanged(bytes32 indexed projectId, bool active);
    
    /**
     * @dev Constructor - sets the token contract address
     * @param _tokenAddress Address of the ProVibeToken contract
     */
    constructor(address _tokenAddress) Ownable(msg.sender) {
        require(_tokenAddress != address(0), "Token address cannot be zero");
        proVibeToken = ProVibeToken(_tokenAddress);
    }
    
    /**
     * @dev Registers a new project
     * @param projectId Unique identifier for the project
     * @param metadataURI URI pointing to the project's metadata
     * @param totalEquity Total equity units for the project
     * @param equityPrice Price per equity unit in ETH (wei)
     */
    function registerProject(
        bytes32 projectId,
        string calldata metadataURI,
        uint256 totalEquity,
        uint256 equityPrice
    ) external {
        require(!projects[projectId].exists, "Project already exists");
        require(totalEquity > 0, "Total equity must be greater than 0");
        
        Project storage newProject = projects[projectId];
        newProject.id = projectId;
        newProject.founder = msg.sender;
        newProject.metadataURI = metadataURI;
        newProject.exists = true;
        newProject.active = true;
        newProject.createdAt = block.timestamp;
        newProject.totalEquity = totalEquity;
        newProject.equityPrice = equityPrice;
        
        projectIds.push(projectId);
        
        // Create tokens for this project
        proVibeToken.createProjectTokens(
            projectId,
            totalEquity,
            defaultFounderPercent,
            defaultDeveloperPercent,
            defaultLegalPercent,
            defaultInvestorPercent
        );
        
        // Distribute founder equity
        proVibeToken.distributeFounderEquity(projectId, msg.sender);
        
        emit ProjectRegistered(projectId, msg.sender, metadataURI);
    }
    
    /**
     * @dev Assigns a developer to a project
     * @param projectId The project identifier
     * @param developer The developer's address
     * @param equityAmount The amount of equity to allocate
     */
    function assignDeveloper(bytes32 projectId, address developer, uint256 equityAmount) external onlyOwner {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        require(project.active, "Project is not active");
        require(developer != address(0), "Developer address cannot be zero");
        require(!project.developerContributions[developer].hasContributed, "Developer already assigned");
        
        // Calculate available developer equity
        uint256 availableDeveloperEquity = proVibeToken.getAvailableTokens(projectId, 2);
        require(equityAmount <= availableDeveloperEquity, "Insufficient developer equity available");
        
        // Add developer contribution
        project.developerContributions[developer] = Contribution({
            equityAmount: equityAmount,
            hasContributed: true,
            equityDistributed: false
        });
        
        project.developers.push(developer);
        
        emit DeveloperAssigned(projectId, developer, equityAmount);
    }
    
    /**
     * @dev Assigns a legal expert to a project
     * @param projectId The project identifier
     * @param legalExpert The legal expert's address
     * @param equityAmount The amount of equity to allocate
     */
    function assignLegalExpert(bytes32 projectId, address legalExpert, uint256 equityAmount) external onlyOwner {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        require(project.active, "Project is not active");
        require(legalExpert != address(0), "Legal expert address cannot be zero");
        require(!project.legalContributions[legalExpert].hasContributed, "Legal expert already assigned");
        
        // Calculate available legal equity
        uint256 availableLegalEquity = proVibeToken.getAvailableTokens(projectId, 3);
        require(equityAmount <= availableLegalEquity, "Insufficient legal equity available");
        
        // Add legal contribution
        project.legalContributions[legalExpert] = Contribution({
            equityAmount: equityAmount,
            hasContributed: true,
            equityDistributed: false
        });
        
        project.legalExperts.push(legalExpert);
        
        emit LegalExpertAssigned(projectId, legalExpert, equityAmount);
    }
    
    /**
     * @dev Processes an investment in a project
     * @param projectId The project identifier
     */
    function invest(bytes32 projectId) external payable {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        require(project.active, "Project is not active");
        require(msg.value > 0, "Investment amount must be greater than 0");
        
        // Calculate how much equity the investment is worth
        uint256 equityAmount = (msg.value * 1e18) / project.equityPrice;
        
        // Check if enough investor equity is available
        uint256 availableInvestorEquity = proVibeToken.getAvailableTokens(projectId, 4);
        require(equityAmount <= availableInvestorEquity, "Insufficient investor equity available");
        
        // Record the investment
        project.investments[msg.sender] = Investment({
            amount: msg.value,
            equityAmount: equityAmount,
            active: true
        });
        
        project.investors.push(msg.sender);
        
        // Distribute equity to the investor
        proVibeToken.distributeInvestorEquity(projectId, msg.sender, equityAmount);
        
        // Transfer ETH to the project founder
        payable(project.founder).transfer(msg.value);
        
        emit InvestmentReceived(projectId, msg.sender, msg.value, equityAmount);
        emit EquityDistributed(projectId, msg.sender, equityAmount);
    }
    
    /**
     * @dev Distributes equity to a developer
     * @param projectId The project identifier
     * @param developer The developer's address
     */
    function distributeDeveloperEquity(bytes32 projectId, address developer) external onlyOwner {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        require(developer != address(0), "Developer address cannot be zero");
        
        Contribution storage contribution = project.developerContributions[developer];
        require(contribution.hasContributed, "Developer has not contributed");
        require(!contribution.equityDistributed, "Developer equity already distributed");
        
        // Mark equity as distributed
        contribution.equityDistributed = true;
        
        // Distribute equity
        proVibeToken.distributeDeveloperEquity(projectId, developer, contribution.equityAmount);
        
        emit EquityDistributed(projectId, developer, contribution.equityAmount);
    }
    
    /**
     * @dev Distributes equity to a legal expert
     * @param projectId The project identifier
     * @param legalExpert The legal expert's address
     */
    function distributeLegalEquity(bytes32 projectId, address legalExpert) external onlyOwner {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        require(legalExpert != address(0), "Legal expert address cannot be zero");
        
        Contribution storage contribution = project.legalContributions[legalExpert];
        require(contribution.hasContributed, "Legal expert has not contributed");
        require(!contribution.equityDistributed, "Legal expert equity already distributed");
        
        // Mark equity as distributed
        contribution.equityDistributed = true;
        
        // Distribute equity
        proVibeToken.distributeLegalEquity(projectId, legalExpert, contribution.equityAmount);
        
        emit EquityDistributed(projectId, legalExpert, contribution.equityAmount);
    }
    
    /**
     * @dev Sets a project's active status
     * @param projectId The project identifier
     * @param active Whether the project is active
     */
    function setProjectStatus(bytes32 projectId, bool active) external onlyOwner {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        
        project.active = active;
        
        emit ProjectStatusChanged(projectId, active);
    }
    
    /**
     * @dev Updates the equity price for a project
     * @param projectId The project identifier
     * @param newPrice New price per equity unit in ETH (wei)
     */
    function updateEquityPrice(bytes32 projectId, uint256 newPrice) external {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        require(msg.sender == project.founder || msg.sender == owner(), "Only founder or contract owner can update price");
        require(newPrice > 0, "Price must be greater than 0");
        
        project.equityPrice = newPrice;
    }
    
    /**
     * @dev Updates the default equity percentages
     * @param founderPercent New founder percentage (in basis points)
     * @param developerPercent New developer percentage (in basis points)
     * @param legalPercent New legal expert percentage (in basis points)
     * @param investorPercent New investor percentage (in basis points)
     */
    function updateDefaultPercentages(
        uint256 founderPercent,
        uint256 developerPercent,
        uint256 legalPercent,
        uint256 investorPercent
    ) external onlyOwner {
        require(founderPercent + developerPercent + legalPercent + investorPercent == 10000, "Percentages must add up to 100%");
        
        defaultFounderPercent = founderPercent;
        defaultDeveloperPercent = developerPercent;
        defaultLegalPercent = legalPercent;
        defaultInvestorPercent = investorPercent;
    }
    
    /**
     * @dev Gets project information
     * @param projectId The project identifier
     * @return exists Whether the project exists
     * @return founder The project founder
     * @return metadataURI The project metadata URI
     * @return active Whether the project is active
     * @return createdAt When the project was created
     * @return totalEquity Total equity units for the project
     * @return equityPrice Price per equity unit in ETH (wei)
     */
    function getProjectInfo(bytes32 projectId) external view returns (
        bool exists,
        address founder,
        string memory metadataURI,
        bool active,
        uint256 createdAt,
        uint256 totalEquity,
        uint256 equityPrice
    ) {
        Project storage project = projects[projectId];
        return (
            project.exists,
            project.founder,
            project.metadataURI,
            project.active,
            project.createdAt,
            project.totalEquity,
            project.equityPrice
        );
    }
    
    /**
     * @dev Gets developer contribution information
     * @param projectId The project identifier
     * @param developer The developer's address
     * @return hasContributed Whether the developer has contributed
     * @return equityAmount The amount of equity allocated
     * @return equityDistributed Whether the equity has been distributed
     */
    function getDeveloperContribution(bytes32 projectId, address developer) external view returns (
        bool hasContributed,
        uint256 equityAmount,
        bool equityDistributed
    ) {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        
        Contribution storage contribution = project.developerContributions[developer];
        return (
            contribution.hasContributed,
            contribution.equityAmount,
            contribution.equityDistributed
        );
    }
    
    /**
     * @dev Gets legal expert contribution information
     * @param projectId The project identifier
     * @param legalExpert The legal expert's address
     * @return hasContributed Whether the legal expert has contributed
     * @return equityAmount The amount of equity allocated
     * @return equityDistributed Whether the equity has been distributed
     */
    function getLegalContribution(bytes32 projectId, address legalExpert) external view returns (
        bool hasContributed,
        uint256 equityAmount,
        bool equityDistributed
    ) {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        
        Contribution storage contribution = project.legalContributions[legalExpert];
        return (
            contribution.hasContributed,
            contribution.equityAmount,
            contribution.equityDistributed
        );
    }
    
    /**
     * @dev Gets investment information
     * @param projectId The project identifier
     * @param investor The investor's address
     * @return amount The investment amount in ETH (wei)
     * @return equityAmount The amount of equity allocated
     * @return active Whether the investment is active
     */
    function getInvestment(bytes32 projectId, address investor) external view returns (
        uint256 amount,
        uint256 equityAmount,
        bool active
    ) {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        
        Investment storage investment = project.investments[investor];
        return (
            investment.amount,
            investment.equityAmount,
            investment.active
        );
    }
    
    /**
     * @dev Gets all project IDs
     * @return Array of project IDs
     */
    function getAllProjectIds() external view returns (bytes32[] memory) {
        return projectIds;
    }
    
    /**
     * @dev Gets the number of developers for a project
     * @param projectId The project identifier
     * @return The number of developers
     */
    function getDeveloperCount(bytes32 projectId) external view returns (uint256) {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        
        return project.developers.length;
    }
    
    /**
     * @dev Gets the developer address at a specific index
     * @param projectId The project identifier
     * @param index The index in the developers array
     * @return The developer's address
     */
    function getDeveloperAt(bytes32 projectId, uint256 index) external view returns (address) {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        require(index < project.developers.length, "Index out of bounds");
        
        return project.developers[index];
    }
    
    /**
     * @dev Gets the number of legal experts for a project
     * @param projectId The project identifier
     * @return The number of legal experts
     */
    function getLegalExpertCount(bytes32 projectId) external view returns (uint256) {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        
        return project.legalExperts.length;
    }
    
    /**
     * @dev Gets the legal expert address at a specific index
     * @param projectId The project identifier
     * @param index The index in the legal experts array
     * @return The legal expert's address
     */
    function getLegalExpertAt(bytes32 projectId, uint256 index) external view returns (address) {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        require(index < project.legalExperts.length, "Index out of bounds");
        
        return project.legalExperts[index];
    }
    
    /**
     * @dev Gets the number of investors for a project
     * @param projectId The project identifier
     * @return The number of investors
     */
    function getInvestorCount(bytes32 projectId) external view returns (uint256) {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        
        return project.investors.length;
    }
    
    /**
     * @dev Gets the investor address at a specific index
     * @param projectId The project identifier
     * @param index The index in the investors array
     * @return The investor's address
     */
    function getInvestorAt(bytes32 projectId, uint256 index) external view returns (address) {
        Project storage project = projects[projectId];
        require(project.exists, "Project does not exist");
        require(index < project.investors.length, "Index out of bounds");
        
        return project.investors[index];
    }
}