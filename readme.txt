# ProVibeCoder.com - Deployment Guide & System Documentation

## Table of Contents

1. [System Overview](#system-overview)
2. [Architecture](#architecture)
3. [Technologies Used](#technologies-used)
4. [Prerequisites](#prerequisites)
5. [Installation & Setup](#installation--setup)
6. [Deployment](#deployment)
7. [API Documentation](#api-documentation)
8. [Smart Contract Interaction](#smart-contract-interaction)
9. [Security Considerations](#security-considerations)
10. [Monitoring & Maintenance](#monitoring--maintenance)
11. [Future Enhancements](#future-enhancements)

## System Overview

ProVibeCoder is a multi-sided marketplace platform designed to connect:

- **Vibe Coders**: Developers who submit AI-generated/assisted code projects
- **Expert Developers**: Professionals who review, debug, and identify security issues
- **Legal Experts**: Lawyers who review code and business models for compliance
- **Investors**: Users who can invest in audited projects based on transparent metrics

The platform manages the entire workflow from code submission through expert review, legal compliance checks, and eventually investment. The equity distribution and reward mechanisms are managed through blockchain smart contracts.

## Architecture

The system consists of three primary components:

1. **Frontend**: React Progressive Web App (PWA)
2. **Backend**: Node.js/Express RESTful API with MongoDB
3. **Blockchain**: Ethereum smart contracts for equity management

### Component Diagram

```
┌────────────────┐      ┌────────────────┐      ┌────────────────┐
│    Frontend    │      │    Backend     │      │   Blockchain   │
│  (React PWA)   │◄────►│ (Node/Express) │◄────►│   (Ethereum)   │
└────────────────┘      └────────────────┘      └────────────────┘
        │                       │                       │
        │                       │                       │
        ▼                       ▼                       ▼
┌────────────────┐      ┌────────────────┐      ┌────────────────┐
│  User Interface│      │    MongoDB     │      │ Smart Contracts│
│  Components    │      │    Database    │      │ - ProVibeToken │
│  - PWA Features│      │  - User Data   │      │ - ProjectReg.  │
│  - Code Editor │      │  - Projects    │      │ - TaskRegistry │
└────────────────┘      └────────────────┘      └────────────────┘
```

### Data Flow

1. Users interact with the React PWA frontend
2. Frontend communicates with the backend API
3. Backend processes requests, interacts with MongoDB and blockchain
4. Smart contracts manage equity distribution and rewards
5. Real-time updates are pushed to users through notifications

## Technologies Used

### Frontend
- React.js
- React Router for navigation
- Context API for state management
- Monaco Editor for code editing
- Progressive Web App features
- Web3.js for blockchain integration

### Backend
- Node.js
- Express.js
- MongoDB with Mongoose
- JSON Web Tokens (JWT) for authentication
- Bcrypt for password hashing
- Web3.js for Ethereum interactions

### Blockchain
- Solidity smart contracts
- Ethereum blockchain
- OpenZeppelin contract libraries
- Truffle Suite for development
- Web3.js for interaction

### DevOps
- Docker for containerization
- NGINX for web serving
- PM2 for Node.js process management
- MongoDB Atlas for database hosting
- Infura for Ethereum node access

## Prerequisites

Before you begin deployment, ensure you have:

1. Node.js (v14+) and npm installed
2. MongoDB (v4+) installed or access to MongoDB Atlas
3. Ethereum node access (via Infura or your own node)
4. Docker and Docker Compose (optional, for containerized deployment)
5. Domain name with SSL certificate
6. AWS account or equivalent for cloud deployment (optional)

## Installation & Setup

### Local Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/provibecoder.git
   cd provibecoder
   ```

2. **Frontend setup:**
   ```bash
   cd frontend
   cp .env.example .env
   # Edit .env with appropriate configuration
   npm install
   npm start
   ```

3. **Backend setup:**
   ```bash
   cd backend
   cp .env.example .env
   # Edit .env with appropriate configuration
   npm install
   npm run dev
   ```

4. **Smart contracts setup:**
   ```bash
   cd contracts
   cp .env.example .env
   # Edit .env with appropriate configuration
   npm install
   npx truffle develop
   truffle(develop)> migrate
   ```

### Configuration Files

#### Frontend (.env)
```
REACT_APP_API_URL=http://localhost:5000/api
REACT_APP_BLOCKCHAIN_NETWORK=development
REACT_APP_INFURA_ID=your_infura_project_id
```

#### Backend (.env)
```
PORT=5000
NODE_ENV=development
FRONTEND_URL=http://localhost:3000
MONGODB_URI=mongodb://localhost:27017/provibecoder
JWT_SECRET=your_jwt_secret_key_here
JWT_EXPIRE=7d
ETH_NODE_URL=http://localhost:8545
ETH_PRIVATE_KEY=your_private_key_without_0x_prefix
ETH_NETWORK=development
```

#### Smart Contracts (.env)
```
INFURA_API_KEY=your_infura_api_key
PRIVATE_KEY=your_private_key_without_0x_prefix
ETHERSCAN_API_KEY=your_etherscan_api_key
OWNER_ADDRESS=0x1234567890123456789012345678901234567890
FEE_RECEIVER_ADDRESS=0x0987654321098765432109876543210987654321
```

## Deployment

### Production Deployment Options

#### Option 1: Traditional Server Deployment

1. **Set up a VPS/Dedicated Server:**
   - Ubuntu 20.04 LTS recommended
   - Configure security (firewalls, SSH)
   - Install Node.js, MongoDB, NGINX

2. **Deploy Frontend:**
   ```bash
   cd frontend
   npm run build
   # Copy the build directory to your web server
   ```

3. **Configure NGINX for Frontend:**
   ```nginx
   server {
     listen 80;
     server_name provibecoder.com www.provibecoder.com;
     
     location / {
       root /var/www/provibecoder/frontend;
       try_files $uri $uri/ /index.html;
     }
     
     location /api {
       proxy_pass http://localhost:5000;
       proxy_http_version 1.1;
       proxy_set_header Upgrade $http_upgrade;
       proxy_set_header Connection 'upgrade';
       proxy_set_header Host $host;
       proxy_cache_bypass $http_upgrade;
     }
   }
   ```

4. **Deploy Backend:**
   ```bash
   cd backend
   npm install --production
   # Set up PM2 process manager
   pm2 start server.js --name provibecoder-api
   ```

5. **Deploy Smart Contracts:**
   ```bash
   cd contracts
   # Deploy to desired network (e.g., mainnet, rinkeby)
   npx truffle migrate --network mainnet
   ```

6. **Set up SSL with Certbot:**
   ```bash
   sudo certbot --nginx -d provibecoder.com -d www.provibecoder.com
   ```

#### Option 2: Docker Deployment

1. **Create Docker Compose File:**
   Create a `docker-compose.yml` file in the project root:

   ```yaml
   version: '3'
   services:
     frontend:
       build: ./frontend
       ports:
         - "3000:80"
       environment:
         - REACT_APP_API_URL=http://api.provibecoder.com/api
       depends_on:
         - backend
     
     backend:
       build: ./backend
       ports:
         - "5000:5000"
       environment:
         - PORT=5000
         - NODE_ENV=production
         - MONGODB_URI=mongodb://mongodb:27017/provibecoder
         - JWT_SECRET=${JWT_SECRET}
         - JWT_EXPIRE=7d
       depends_on:
         - mongodb
     
     mongodb:
       image: mongo:latest
       ports:
         - "27017:27017"
       volumes:
         - mongo_data:/data/db
   
   volumes:
     mongo_data:
   ```

2. **Build and run the containers:**
   ```bash
   docker-compose up -d
   ```

3. **Deploy smart contracts separately:**
   ```bash
   cd contracts
   # Deploy to desired network
   npx truffle migrate --network mainnet
   ```

#### Option 3: Cloud Deployment (AWS)

1. **Frontend:**
   - Deploy to AWS S3 and CloudFront for global CDN
   - Set up Route 53 for custom domain

2. **Backend:**
   - Deploy to AWS Elastic Beanstalk or ECS
   - Use RDS or DocumentDB for MongoDB

3. **Smart Contracts:**
   - Deploy to mainnet from secure environment
   - Store contract addresses in parameter store

## API Documentation

### Authentication Endpoints

| Method | Endpoint | Description | Access |
|--------|----------|-------------|--------|
| POST | `/api/auth/register` | Register new user | Public |
| POST | `/api/auth/login` | User login | Public |
| GET | `/api/auth/me` | Get current user | Private |
| GET | `/api/auth/verify-email/:token` | Verify email | Public |
| POST | `/api/auth/forgot-password` | Request password reset | Public |
| PUT | `/api/auth/reset-password/:token` | Reset password | Public |
| PUT | `/api/auth/update-profile` | Update user profile | Private |

### Project Endpoints

| Method | Endpoint | Description | Access |
|--------|----------|-------------|--------|
| GET | `/api/projects` | Get all projects | Private |
| GET | `/api/projects/:id` | Get single project | Private |
| POST | `/api/projects` | Create new project | Private (VC) |
| PUT | `/api/projects/:id` | Update project | Private (VC) |
| DELETE | `/api/projects/:id` | Delete project | Private (VC) |
| PUT | `/api/projects/:id/files` | Update project files | Private (VC/ED) |
| GET | `/api/projects/awaiting-review` | Get projects awaiting review | Private (ED) |
| GET | `/api/projects/awaiting-legal` | Get projects awaiting legal | Private (LE) |
| GET | `/api/projects/audited` | Get audited projects | Private (I) |
| POST | `/api/projects/:id/complete-review` | Complete project review | Private (ED) |
| POST | `/api/projects/:id/complete-legal` | Complete legal review | Private (LE) |

### Review Endpoints

| Method | Endpoint | Description | Access |
|--------|----------|-------------|--------|
| POST | `/api/reviews` | Create a review | Private (ED) |
| GET | `/api/reviews/project/:projectId` | Get all reviews for a project | Private |
| GET | `/api/reviews/:id` | Get single review | Private |
| PUT | `/api/reviews/:id` | Update review | Private (ED/VC) |
| POST | `/api/reviews/:id/comments` | Add comment to review | Private (ED/VC) |
| DELETE | `/api/reviews/:id` | Delete review | Private (ED/Admin) |
| POST | `/api/reviews/complete/:projectId` | Complete review of a project | Private (ED) |

### Legal Review Endpoints

| Method | Endpoint | Description | Access |
|--------|----------|-------------|--------|
| POST | `/api/legal/reviews` | Create a legal review | Private (LE) |
| GET | `/api/legal/reviews/project/:projectId` | Get reviews for project | Private |
| GET | `/api/legal/documents/:projectId` | Get legal docs for project | Private |
| POST | `/api/legal/documents` | Upload legal document | Private (LE) |
| GET | `/api/legal/compliance-checklist` | Get compliance checklist | Private (LE) |

### Investment Endpoints

| Method | Endpoint | Description | Access |
|--------|----------|-------------|--------|
| POST | `/api/investments` | Create investment | Private (I) |
| GET | `/api/investments/user/:userId` | Get user investments | Private |
| GET | `/api/investments/project/:projectId` | Get project investments | Private |
| GET | `/api/investments/metrics/:userId` | Get investment metrics | Private |

### Blockchain Endpoints

| Method | Endpoint | Description | Access |
|--------|----------|-------------|--------|
| POST | `/api/blockchain/register-project/:id` | Register project on blockchain | Private (Admin) |
| POST | `/api/blockchain/assign-developer` | Assign developer | Private (Admin) |
| POST | `/api/blockchain/assign-legal-expert` | Assign legal expert | Private (Admin) |
| POST | `/api/blockchain/process-investment` | Process investment | Private (Admin) |
| POST | `/api/blockchain/create-task` | Create task | Private (Admin) |
| GET | `/api/blockchain/project/:id` | Get project info | Private |
| GET | `/api/blockchain/balance/:address` | Get token balance | Private |

## Smart Contract Interaction

### Contract Addresses

After deployment, you'll need to update the following contract addresses in the backend `.env` file:

```
CONTRACT_TOKEN_ADDRESS=0x...
CONTRACT_PROJECT_REGISTRY_ADDRESS=0x...
CONTRACT_TASK_REGISTRY_ADDRESS=0x...
```

### Main Functions

1. **ProVibeToken Contract:**
   - Creating project tokens
   - Distributing equity to participants
   - Tracking equity allocation

2. **ProjectRegistry Contract:**
   - Registering projects on the blockchain
   - Assigning developers and legal experts
   - Processing investments
   - Distributing equity

3. **TaskRegistry Contract:**
   - Creating tasks for projects
   - Assigning tasks to contributors
   - Completing tasks and triggering rewards

### Ethereum Network Selection

The system supports multiple Ethereum networks:
- **Development**: Local blockchain (ganache/truffle develop)
- **Test networks**: Rinkeby, Kovan, Görli
- **Mainnet**: Production Ethereum network

Configure the desired network in the `.env` files.

## Security Considerations

### Authentication & Authorization

- JWT tokens are used for API authentication
- HTTPS should be enforced for all production traffic
- Role-based access control is implemented for all routes
- Token expiration and rotation policies should be enforced

### Data Protection

- Sensitive data is encrypted in the database
- Password hashing uses bcrypt with appropriate salt rounds
- Input validation is performed on all API endpoints
- Database access is restricted by IP in production

### Smart Contract Security

- Smart contracts have been audited for common vulnerabilities
- Access control is implemented for sensitive functions
- Gas optimization has been considered in contract design
- Emergency stop mechanisms are available if needed

### User Wallet Security

- Private keys are never stored on the server
- Users manage their own wallets (MetaMask or similar)
- Transaction signing happens client-side
- Server-side operations use a dedicated admin wallet

## Monitoring & Maintenance

### Backend Monitoring

- Set up PM2 for process monitoring
- Implement logging with Winston or similar
- Set up alerts for server issues
- Monitor API response times and error rates

### Database Maintenance

- Set up regular backups
- Implement indexing strategy for performance
- Monitor database size and performance
- Consider sharding for large-scale deployments

### Blockchain Monitoring

- Monitor gas prices for optimal transaction timing
- Set up alerts for failed transactions
- Track contract events for verification
- Maintain a transaction history for auditing

### Frontend Analytics

- Implement analytics for user engagement
- Track conversion rates through the platform
- Monitor PWA performance metrics
- Test cross-browser and device compatibility

## Future Enhancements

### Technical Enhancements

1. **Scalability Improvements:**
   - Implement microservices architecture
   - Add Redis caching layer
   - Optimize database queries
   - Consider serverless functions for specific endpoints

2. **Enhanced Blockchain Integration:**
   - Support multiple blockchain networks
   - Add Layer 2 solutions for lower fees
   - Implement token swapping features
   - Add support for NFT representation of projects

3. **Developer Experience:**
   - Improve code editor capabilities
   - Add integrated testing framework
   - Support more programming languages
   - Enhance Git integration

4. **Mobile Experience:**
   - Develop native mobile apps
   - Enhance offline capabilities
   - Improve mobile code review experience
   - Add biometric authentication

### Business Enhancements

1. **Marketplace Expansion:**
   - Add tiered membership levels
   - Implement reputation system
   - Create featured projects section
   - Develop community forums

2. **Analytics Dashboard:**
   - Project performance metrics
   - Investment analytics
   - Developer productivity metrics
   - Legal compliance tracking

3. **Integration Capabilities:**
   - GitHub/GitLab integration
   - CI/CD pipeline connections
   - Legal document management systems
   - Payment processor options

4. **Revenue Streams:**
   - Premium subscription tiers
   - Featured listings
   - Priority review services
   - Escrow services for investments

---

This deployment guide covers the essential aspects of setting up and maintaining the ProVibeCoder platform. For specific technical questions or troubleshooting, refer to the README files in each component directory or contact the development team.