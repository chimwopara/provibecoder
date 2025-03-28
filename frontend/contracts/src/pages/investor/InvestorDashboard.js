// File: frontend/src/pages/investor/InvestorDashboard.js
import React, { useState, useEffect, useContext } from 'react';
import { Link } from 'react-router-dom';
import { AuthContext } from '../../context/AuthContext';
import { NotificationContext } from '../../context/NotificationContext';
import ProjectCard from '../../components/projects/ProjectCard';
import MetricsChart from '../../components/charts/MetricsChart';
import InvestmentSummary from '../../components/investor/InvestmentSummary';
import api from '../../services/api';
import '../../styles/InvestorDashboard.css';

const InvestorDashboard = () => {
  const { user } = useContext(AuthContext);
  const { addNotification } = useContext(NotificationContext);
  
  const [auditedProjects, setAuditedProjects] = useState([]);
  const [investments, setInvestments] = useState([]);
  const [metrics, setMetrics] = useState({
    totalInvested: 0,
    totalProjects: 0,
    averageReturn: 0,
    portfolioGrowth: []
  });
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    const fetchData = async () => {
      try {
        // Fetch audited projects available for investment
        const projectsRes = await api.get('/api/projects/audited');
        setAuditedProjects(projectsRes.data);
        
        // Fetch current user's investments
        const investmentsRes = await api.get(`/api/investments/user/${user._id}`);
        setInvestments(investmentsRes.data);
        
        // Fetch investment metrics
        const metricsRes = await api.get(`/api/investments/metrics/${user._id}`);
        setMetrics(metricsRes.data);
      } catch (err) {
        console.error('Error fetching dashboard data:', err);
        addNotification('Failed to load dashboard data', 'error');
      } finally {
        setLoading(false);
      }
    };
    
    fetchData();
  }, [user._id, addNotification]);
  
  if (loading) {
    return <div className="loading">Loading dashboard data...</div>;
  }
  
  return (
    <div className="investor-dashboard-container">
      <h1>Investor Dashboard</h1>
      
      <div className="dashboard-grid">
        <div className="metrics-section">
          <h2>Investment Portfolio</h2>
          
          <div className="metrics-cards">
            <div className="metric-card">
              <h3>Total Invested</h3>
              <p className="metric-value">${metrics.totalInvested.toLocaleString()}</p>
            </div>
            
            <div className="metric-card">
              <h3>Projects Backed</h3>
              <p className="metric-value">{metrics.totalProjects}</p>
            </div>
            
            <div className="metric-card">
              <h3>Average Return</h3>
              <p className="metric-value">{metrics.averageReturn}%</p>
            </div>
          </div>
          
          <div className="chart-container">
            <h3>Portfolio Growth</h3>
            <MetricsChart 
              data={metrics.portfolioGrowth} 
              xKey="month" 
              yKey="value" 
              lineLabel="Portfolio Value" 
            />
          </div>
          
          <div className="investments-list">
            <h3>My Investments</h3>
            {investments.length > 0 ? (
              <InvestmentSummary investments={investments} />
            ) : (
              <p className="no-data-message">
                You haven't made any investments yet. 
                Explore the opportunities below to get started.
              </p>
            )}
          </div>
        </div>
        
        <div className="opportunities-section">
          <div className="section-header">
            <h2>Investment Opportunities</h2>
            <Link to="/investment-opportunities" className="view-all-link">
              View All
            </Link>
          </div>
          
          <div className="project-cards">
            {auditedProjects.length > 0 ? (
              auditedProjects.slice(0, 4).map(project => (
                <ProjectCard 
                  key={project._id} 
                  project={project}
                  showInvestButton={true}
                  linkTo={`/project-metrics/${project._id}`}
                />
              ))
            ) : (
              <p className="no-data-message">
                No investment opportunities available at the moment. 
                Check back soon!
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default InvestorDashboard;