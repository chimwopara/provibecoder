import React, { useState, useEffect } from 'react';
import { initBlockchain, getAccount, getTokenBalance } from '../../services/blockchainService';

const WalletConnect = () => {
  const [isConnected, setIsConnected] = useState(false);
  const [account, setAccount] = useState('');
  const [balance, setBalance] = useState('0');
  
  const connectWallet = async () => {
    const success = await initBlockchain();
    if (success) {
      const userAccount = await getAccount();
      if (userAccount) {
        setAccount(userAccount);
        const tokenBalance = await getTokenBalance(userAccount);
        setBalance(tokenBalance);
        setIsConnected(true);
      }
    }
  };
  
  return (
    <div className="wallet-container">
      <h2>Blockchain Wallet</h2>
      
      {isConnected ? (
        <div>
          <p><strong>Connected Account:</strong> {account}</p>
          <p><strong>Token Balance:</strong> {balance} PVT</p>
        </div>
      ) : (
        <button onClick={connectWallet}>Connect Wallet</button>
      )}
    </div>
  );
};

export default WalletConnect;