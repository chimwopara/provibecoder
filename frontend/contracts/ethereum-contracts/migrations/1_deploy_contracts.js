const ProVibeToken = artifacts.require("ProVibeToken");
const ProjectRegistry = artifacts.require("ProjectRegistry");
const TaskRegistry = artifacts.require("TaskRegistry");

module.exports = async function(deployer, network, accounts) {
  const owner = accounts[0];
  const feeReceiver = accounts[1];
  
  // Deploy the token contract
  await deployer.deploy(ProVibeToken, owner, feeReceiver);
  const tokenInstance = await ProVibeToken.deployed();
  
  // Deploy the project registry contract
  await deployer.deploy(ProjectRegistry, tokenInstance.address);
  const projectInstance = await ProjectRegistry.deployed();
  
  // Deploy the task registry contract
  await deployer.deploy(TaskRegistry, projectInstance.address);
  
  console.log("Deployment completed successfully!");
  console.log("ProVibeToken deployed at:", tokenInstance.address);
  console.log("ProjectRegistry deployed at:", projectInstance.address);
  console.log("TaskRegistry deployed at:", await TaskRegistry.deployed().address);
};