// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./ProjectRegistry.sol";

/**
 * @title TaskRegistry
 * @dev Registry for managing tasks and rewards on the ProVibeCoder platform
 * This contract manages the assignment and completion of tasks for
 * developers and legal experts
 */
contract TaskRegistry is Ownable {
    // Reference to the ProjectRegistry contract
    ProjectRegistry public projectRegistry;
    
    // Task status options
    enum TaskStatus { Available, Assigned, Completed, Cancelled }
    
    // Task type options
    enum TaskType { Development, Security, Legal }
    
    // Task structure
    struct Task {
        bytes32 id;
        bytes32 projectId;
        string title;
        string description;
        TaskType taskType;
        uint256 equityReward;
        address assignee;
        address creator;
        TaskStatus status;
        uint256 createdAt;
        uint256 assignedAt;
        uint256 completedAt;
        string deliverableURI;
        bool exists;
    }
    
    // Mapping from task ID to Task
    mapping(bytes32 => Task) private tasks;
    
    // Mapping from project ID to array of task IDs
    mapping(bytes32 => bytes32[]) private projectTasks;
    
    // Events
    event TaskCreated(bytes32 indexed taskId, bytes32 indexed projectId, string title, TaskType taskType, uint256 equityReward);
    event TaskAssigned(bytes32 indexed taskId, address indexed assignee, uint256 assignedAt);
    event TaskCompleted(bytes32 indexed taskId, string deliverableURI, uint256 completedAt);
    event TaskCancelled(bytes32 indexed taskId);
    
    /**
     * @dev Constructor - sets the project registry contract address
     * @param _projectRegistryAddress Address of the ProjectRegistry contract
     */
    constructor(address _projectRegistryAddress) Ownable(msg.sender) {
        require(_projectRegistryAddress != address(0), "Project registry address cannot be zero");
        projectRegistry = ProjectRegistry(_projectRegistryAddress);
    }
    
    /**
     * @dev Creates a new task
     * @param taskId Unique identifier for the task
     * @param projectId The project identifier
     * @param title The task title
     * @param description The task description
     * @param taskType The type of task (Development, Security, Legal)
     * @param equityReward The amount of equity tokens to reward
     */
    function createTask(
        bytes32 taskId,
        bytes32 projectId,
        string calldata title,
        string calldata description,
        TaskType taskType,
        uint256 equityReward
    ) external {
        // Check if task exists
        require(!tasks[taskId].exists, "Task already exists");
        
        // Check project info
        (bool exists, address founder, , bool active, , , ) = projectRegistry.getProjectInfo(projectId);
        require(exists, "Project does not exist");
        require(active, "Project is not active");
        
        // Only project founder or contract owner can create tasks
        require(msg.sender == founder || msg.sender == owner(), "Only project founder or contract owner can create tasks");
        
        // Create the task
        Task storage newTask = tasks[taskId];
        newTask.id = taskId;
        newTask.projectId = projectId;
        newTask.title = title;
        newTask.description = description;
        newTask.taskType = taskType;
        newTask.equityReward = equityReward;
        newTask.creator = msg.sender;
        newTask.status = TaskStatus.Available;
        newTask.createdAt = block.timestamp;
        newTask.exists = true;
        
        // Add to project tasks
        projectTasks[projectId].push(taskId);
        
        emit TaskCreated(taskId, projectId, title, taskType, equityReward);
    }
    
    /**
     * @dev Assigns a task to a developer or legal expert
     * @param taskId The task identifier
     * @param assignee The address of the assignee
     */
    function assignTask(bytes32 taskId, address assignee) external onlyOwner {
        Task storage task = tasks[taskId];
        require(task.exists, "Task does not exist");
        require(task.status == TaskStatus.Available, "Task is not available");
        require(assignee != address(0), "Assignee address cannot be zero");
        
        // Check if project is active
        (, , , bool active, , , ) = projectRegistry.getProjectInfo(task.projectId);
        require(active, "Project is not active");
        
        // Assign the task
        task.assignee = assignee;
        task.status = TaskStatus.Assigned;
        task.assignedAt = block.timestamp;
        
        // If task is development or security, assign developer
        if (task.taskType == TaskType.Development || task.taskType == TaskType.Security) {
            // Check if developer is already assigned to this project
            (bool hasContributed, , ) = projectRegistry.getDeveloperContribution(task.projectId, assignee);
            
            if (!hasContributed) {
                // Assign developer to project
                projectRegistry.assignDeveloper(task.projectId, assignee, task.equityReward);
            }
        } 
        // If task is legal, assign legal expert
        else if (task.taskType == TaskType.Legal) {
            // Check if legal expert is already assigned to this project
            (bool hasContributed, , ) = projectRegistry.getLegalContribution(task.projectId, assignee);
            
            if (!hasContributed) {
                // Assign legal expert to project
                projectRegistry.assignLegalExpert(task.projectId, assignee, task.equityReward);
            }
        }
        
        emit TaskAssigned(taskId, assignee, task.assignedAt);
    }
    
    /**
     * @dev Marks a task as completed
     * @param taskId The task identifier
     * @param deliverableURI URI pointing to the deliverable
     */
    function completeTask(bytes32 taskId, string calldata deliverableURI) external onlyOwner {
        Task storage task = tasks[taskId];
        require(task.exists, "Task does not exist");
        require(task.status == TaskStatus.Assigned, "Task is not assigned");
        
        // Mark task as completed
        task.status = TaskStatus.Completed;
        task.completedAt = block.timestamp;
        task.deliverableURI = deliverableURI;
        
        // Distribute equity based on task type
        if (task.taskType == TaskType.Development || task.taskType == TaskType.Security) {
            projectRegistry.distributeDeveloperEquity(task.projectId, task.assignee);
        } else if (task.taskType == TaskType.Legal) {
            projectRegistry.distributeLegalEquity(task.projectId, task.assignee);
        }
        
        emit TaskCompleted(taskId, deliverableURI, task.completedAt);
    }
    
    /**
     * @dev Cancels a task
     * @param taskId The task identifier
     */
    function cancelTask(bytes32 taskId) external {
        Task storage task = tasks[taskId];
        require(task.exists, "Task does not exist");
        require(task.status != TaskStatus.Completed && task.status != TaskStatus.Cancelled, "Task already completed or cancelled");
        
        // Only task creator or contract owner can cancel
        require(msg.sender == task.creator || msg.sender == owner(), "Only task creator or contract owner can cancel");
        
        // Mark task as cancelled
        task.status = TaskStatus.Cancelled;
        
        emit TaskCancelled(taskId);
    }
    
    /**
     * @dev Gets task information
     * @param taskId The task identifier
     * @return id The task ID
     * @return projectId The project ID
     * @return title The task title
     * @return description The task description
     * @return taskType The task type
     * @return equityReward The equity reward amount
     * @return assignee The assignee address
     * @return creator The creator address
     * @return status The task status
     * @return createdAt When the task was created
     * @return assignedAt When the task was assigned
     * @return completedAt When the task was completed
     * @return deliverableURI The deliverable URI
     */
    function getTaskInfo(bytes32 taskId) external view returns (
        bytes32 id,
        bytes32 projectId,
        string memory title,
        string memory description,
        TaskType taskType,
        uint256 equityReward,
        address assignee,
        address creator,
        TaskStatus status,
        uint256 createdAt,
        uint256 assignedAt,
        uint256 completedAt,
        string memory deliverableURI
    ) {
        Task storage task = tasks[taskId];
        require(task.exists, "Task does not exist");
        
        return (
            task.id,
            task.projectId,
            task.title,
            task.description,
            task.taskType,
            task.equityReward,
            task.assignee,
            task.creator,
            task.status,
            task.createdAt,
            task.assignedAt,
            task.completedAt,
            task.deliverableURI
        );
    }
    
    /**
     * @dev Gets all task IDs for a project
     * @param projectId The project identifier
     * @return Array of task IDs
     */
    function getProjectTasks(bytes32 projectId) external view returns (bytes32[] memory) {
        return projectTasks[projectId];
    }
    
    /**
     * @dev Gets tasks by status for a project
     * @param projectId The project identifier
     * @param status The task status to filter by
     * @return Array of task IDs
     */
    function getTasksByStatus(bytes32 projectId, TaskStatus status) external view returns (bytes32[] memory) {
        bytes32[] memory allTasks = projectTasks[projectId];
        
        // Count tasks with specified status
        uint256 count = 0;
        for (uint256 i = 0; i < allTasks.length; i++) {
            if (tasks[allTasks[i]].status == status) {
                count++;
            }
        }
        
        // Create array of matching tasks
        bytes32[] memory result = new bytes32[](count);
        uint256 index = 0;
        
        for (uint256 i = 0; i < allTasks.length; i++) {
            if (tasks[allTasks[i]].status == status) {
                result[index] = allTasks[i];
                index++;
            }
        }
        
        return result;
    }
    
    /**
     * @dev Gets tasks assigned to a specific user
     * @param assignee The assignee address
     * @return Array of task IDs
     */
    function getAssigneeTasks(address assignee) external view returns (bytes32[] memory) {
        bytes32[] memory projectIds = projectRegistry.getAllProjectIds();
        
        // Count all tasks assigned to user
        uint256 count = 0;
        for (uint256 i = 0; i < projectIds.length; i++) {
            bytes32[] memory pTasks = projectTasks[projectIds[i]];
            for (uint256 j = 0; j < pTasks.length; j++) {
                if (tasks[pTasks[j]].assignee == assignee) {
                    count++;
                }
            }
        }
        
        // Create array of matching tasks
        bytes32[] memory result = new bytes32[](count);
        uint256 index = 0;
        
        for (uint256 i = 0; i < projectIds.length; i++) {
            bytes32[] memory pTasks = projectTasks[projectIds[i]];
            for (uint256 j = 0; j < pTasks.length; j++) {
                if (tasks[pTasks[j]].assignee == assignee) {
                    result[index] = pTasks[j];
                    index++;
                }
            }
        }
        
        return result;
    }
}