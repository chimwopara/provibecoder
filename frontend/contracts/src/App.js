// File: frontend/src/App.js
import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { NotificationProvider } from './context/NotificationContext';
import PrivateRoute from './components/routing/PrivateRoute';
import RoleRoute from './components/routing/RoleRoute';
import WalletConnect from './components/blockchain/WalletConnect';
// Layout Components
import Navbar from './components/layout/Navbar';
import Footer from './components/layout/Footer';
import Sidebar from './components/layout/Sidebar';
import NotificationCenter from './components/notifications/NotificationCenter';
// Auth Pages
import Login from './pages/auth/Login';
import Register from './pages/auth/Register';
import ForgotPassword from './pages/auth/ForgotPassword';
// Common Pages
import Dashboard from './pages/dashboard/Dashboard';
import Profile from './pages/profile/Profile';
import NotFound from './pages/NotFound';
// Vibe Coder Pages
import CodeSubmission from './pages/vibecoder/CodeSubmission';
import ProjectList from './pages/vibecoder/ProjectList';
import ProjectDetails from './pages/vibecoder/ProjectDetails';
// Expert Developer Pages
import ReviewDashboard from './pages/developer/ReviewDashboard';
import CodeReview from './pages/developer/CodeReview';
import ResolvedIssues from './pages/developer/ResolvedIssues';
// Legal Expert Pages
import LegalDashboard from './pages/legal/LegalDashboard';
import LegalReview from './pages/legal/LegalReview';
import ComplianceReports from './pages/legal/ComplianceReports';
// Investor Pages
import InvestorDashboard from './pages/investor/InvestorDashboard';
import ProjectMetrics from './pages/investor/ProjectMetrics';
import InvestmentOpportunities from './pages/investor/InvestmentOpportunities';
import './styles/App.css';

const App = () => {
  return (
    <AuthProvider>
      <NotificationProvider>
        <Router>
          <div className="app-container">
            <Navbar />
            <div className="content-wrapper">
              <Sidebar />
              <div style={{ 
                display: 'flex', 
                flexDirection: 'column', 
                width: '100%' 
              }}>
                <div style={{ 
                  backgroundColor: '#f5f7fa', 
                  borderRadius: '8px', 
                  padding: '15px', 
                  boxShadow: '0 2px 10px rgba(0, 0, 0, 0.1)', 
                  margin: '10px' 
                }}>
                  <WalletConnect />
                </div>
                <main className="main-content">
                  <Routes>
                    {/* Public Routes */}
                    <Route path="/login" element={<Login />} />
                    <Route path="/register" element={<Register />} />
                    <Route path="/forgot-password" element={<ForgotPassword />} />
                    
                    {/* Private Routes - All Authenticated Users */}
                    <Route element={<PrivateRoute />}>
                      <Route path="/dashboard" element={<Dashboard />} />
                      <Route path="/profile" element={<Profile />} />
                    </Route>
                    
                    {/* Vibe Coder Routes */}
                    <Route element={<RoleRoute role="vibeCoder" />}>
                      <Route path="/submit-code" element={<CodeSubmission />} />
                      <Route path="/my-projects" element={<ProjectList />} />
                      <Route path="/projects/:id" element={<ProjectDetails />} />
                    </Route>
                    
                    {/* Expert Developer Routes */}
                    <Route element={<RoleRoute role="expertDeveloper" />}>
                      <Route path="/review-dashboard" element={<ReviewDashboard />} />
                      <Route path="/code-review/:id" element={<CodeReview />} />
                      <Route path="/resolved-issues" element={<ResolvedIssues />} />
                    </Route>
                    
                    {/* Legal Expert Routes */}
                    <Route element={<RoleRoute role="legalExpert" />}>
                      <Route path="/legal-dashboard" element={<LegalDashboard />} />
                      <Route path="/legal-review/:id" element={<LegalReview />} />
                      <Route path="/compliance-reports" element={<ComplianceReports />} />
                    </Route>
                    
                    {/* Investor Routes */}
                    <Route element={<RoleRoute role="investor" />}>
                      <Route path="/investor-dashboard" element={<InvestorDashboard />} />
                      <Route path="/project-metrics/:id" element={<ProjectMetrics />} />
                      <Route path="/investment-opportunities" element={<InvestmentOpportunities />} />
                    </Route>
                    
                    {/* Fallback Routes */}
                    <Route path="/" element={<Navigate replace to="/dashboard" />} />
                    <Route path="*" element={<NotFound />} />
                  </Routes>
                </main>
              </div>
            </div>
            <NotificationCenter />
            <Footer />
          </div>
        </Router>
      </NotificationProvider>
    </AuthProvider>
  );
};

export default App;