import Web3 from 'web3';
import { CONTRACT_ADDRESSES, NETWORK_CONFIG } from '../contractConfig';

// ABI files (these describe how to interact with the contracts)
import TokenABI from '../contracts/abis/ProVibeToken.json';
import ProjectRegistryABI from '../contracts/abis/ProjectRegistry.json';
import TaskRegistryABI from '../contracts/abis/TaskRegistry.json';

let web3;
let tokenContract;
let projectContract;
let taskContract;

// Initialize connection to blockchain
export const initBlockchain = async () => {
  try {
    // Check if MetaMask is installed
    if (window.ethereum) {
      web3 = new Web3(window.ethereum);
      try {
        // Request account access
        await window.ethereum.request({ method: 'eth_requestAccounts' });
      } catch (error) {
        console.error("User denied account access");
        return false;
      }
    } 
    // If no MetaMask, use local provider
    else {
      web3 = new Web3(new Web3.providers.HttpProvider(NETWORK_CONFIG.rpcUrl));
    }
    
    // Initialize contract instances
    tokenContract = new web3.eth.Contract(
      TokenABI.abi,
      CONTRACT_ADDRESSES.token
    );
    
    projectContract = new web3.eth.Contract(
      ProjectRegistryABI.abi,
      CONTRACT_ADDRESSES.projectRegistry
    );
    
    taskContract = new web3.eth.Contract(
      TaskRegistryABI.abi,
      CONTRACT_ADDRESSES.taskRegistry
    );
    
    return true;
  } catch (error) {
    console.error("Blockchain initialization error:", error);
    return false;
  }
};

// Get current user's account
export const getAccount = async () => {
  try {
    const accounts = await web3.eth.getAccounts();
    return accounts[0];
  } catch (error) {
    console.error("Error getting account:", error);
    return null;
  }
};

// Get token balance for an address
export const getTokenBalance = async (address) => {
  try {
    const balance = await tokenContract.methods.balanceOf(address).call();
    return web3.utils.fromWei(balance, 'ether');
  } catch (error) {
    console.error("Error getting token balance:", error);
    return '0';
  }
};