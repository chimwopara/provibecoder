// File: frontend/src/pages/legal/LegalReview.js
import React, { useState, useEffect, useContext } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { AuthContext } from '../../context/AuthContext';
import { NotificationContext } from '../../context/NotificationContext';
import CodeEditor from '../../components/code/CodeEditor';
import DocumentViewer from '../../components/legal/DocumentViewer';
import ComplianceChecklist from '../../components/legal/ComplianceChecklist';
import LegalReportGenerator from '../../components/legal/LegalReportGenerator';
import api from '../../services/api';
import '../../styles/LegalReview.css';

const LegalReview = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const { user } = useContext(AuthContext);
  const { addNotification } = useContext(NotificationContext);
  
  const [project, setProject] = useState(null);
  const [codeFiles, setCodeFiles] = useState([]);
  const [currentFile, setCurrentFile] = useState(0);
  const [legalDocuments, setLegalDocuments] = useState([]);
  const [businessModelDoc, setBusinessModelDoc] = useState('');
  const [complianceItems, setComplianceItems] = useState([]);
  const [legalNotes, setLegalNotes] = useState('');
  const [loading, setLoading] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [activeTab, setActiveTab] = useState('code');
  
  useEffect(() => {
    const fetchProject = async () => {
      try {
        const res = await api.get(`/api/projects/${id}`);
        setProject(res.data);
        setCodeFiles(res.data.files);
        setBusinessModelDoc(res.data.businessModel || '');
        
        // Fetch legal documents for this project
        const docsRes = await api.get(`/api/legal/documents/${id}`);
        setLegalDocuments(docsRes.data);
        
        // Fetch compliance checklist items
        const checklistRes = await api.get('/api/legal/compliance-checklist');
        setComplianceItems(
          checklistRes.data.map(item => ({
            ...item,
            checked: false,
            notes: ''
          }))
        );
        
        // Fetch existing legal review if any
        const reviewRes = await api.get(`/api/legal/reviews/project/${id}`);
        if (reviewRes.data) {
          setLegalNotes(reviewRes.data.notes || '');
          
          // Update checklist with saved values
          if (reviewRes.data.complianceChecklist) {
            setComplianceItems(reviewRes.data.complianceChecklist);
          }
        }
      } catch (err) {
        console.error('Error fetching project:', err);
        addNotification('Failed to load project data', 'error');
        navigate('/legal-dashboard');
      } finally {
        setLoading(false);
      }
    };
    
    fetchProject();
  }, [id, navigate, addNotification]);
  
  const handleFileChange = (index) => {
    setCurrentFile(index);
  };
  
  const handleChecklistChange = (index, field, value) => {
    const updatedItems = [...complianceItems];
    updatedItems[index][field] = value;
    setComplianceItems(updatedItems);
  };
  
  const handleNotesChange = (e) => {
    setLegalNotes(e.target.value);
  };
  
  const handleSubmitReview = async () => {
    setIsSubmitting(true);
    
    try {
      // Calculate compliance score
      const totalItems = complianceItems.length;
      const checkedItems = complianceItems.filter(item => item.checked).length;
      const complianceScore = Math.round((checkedItems / totalItems) * 100);
      
      // Prepare legal review data
      const reviewData = {
        projectId: id,
        reviewerId: user._id,
        reviewerName: `${user.firstName} ${user.lastName}`,
        complianceChecklist: complianceItems,
        notes: legalNotes,
        complianceScore,
        status: 'completed',
        completedAt: new Date()
      };
      
      // Submit legal review
      await api.post('/api/legal/reviews', reviewData);
      
      addNotification('Legal review submitted successfully', 'success');
      navigate('/legal-dashboard');
    } catch (err) {
      console.error('Error submitting review:', err);
      addNotification('Failed to submit review', 'error');
    } finally {
      setIsSubmitting(false);
    }
  };
  
  if (loading) {
    return <div className="loading">Loading project data...</div>;
  }
  
  return (
    <div className="legal-review-container">
      <div className="review-header">
        <h1>{project.title} - Legal Review</h1>
        <div className="review-actions">
          <button 
            className="submit-review-btn" 
            onClick={handleSubmitReview}
            disabled={isSubmitting}
          >
            {isSubmitting ? 'Submitting...' : 'Submit Legal Review'}
          </button>
        </div>
      </div>
      
      <div className="tab-navigation">
        <button 
          className={`tab-btn ${activeTab === 'code' ? 'active' : ''}`}
          onClick={() => setActiveTab('code')}
        >
          Code Review
        </button>
        <button 
          className={`tab-btn ${activeTab === 'business' ? 'active' : ''}`}
          onClick={() => setActiveTab('business')}
        >
          Business Model
        </button>
        <button 
          className={`tab-btn ${activeTab === 'compliance' ? 'active' : ''}`}
          onClick={() => setActiveTab('compliance')}
        >
          Compliance Checklist
        </button>
        <button 
          className={`tab-btn ${activeTab === 'report' ? 'active' : ''}`}
          onClick={() => setActiveTab('report')}
        >
          Generate Report
        </button>
      </div>
      
      <div className="tab-content">
        {activeTab === 'code' && (
          <div className="code-review-tab">
            <div className="file-tabs">
              {codeFiles.map((file, index) => (
                <button
                  key={index}
                  className={`file-tab ${currentFile === index ? 'active' : ''}`}
                  onClick={() => handleFileChange(index)}
                >
                  {file.name}
                </button>
              ))}
            </div>
            
            <CodeEditor
              language={codeFiles[currentFile].language}
              value={codeFiles[currentFile].content}
              readOnly={true}
            />
            
            <div className="legal-notes-section">
              <h3>Legal Notes on Code</h3>
              <textarea
                className="legal-notes-input"
                value={legalNotes}
                onChange={handleNotesChange}
                placeholder="Add your legal notes regarding code licensing, intellectual property concerns, etc."
                rows={5}
              />
            </div>
          </div>
        )}
        
        {activeTab === 'business' && (
          <div className="business-model-tab">
            <DocumentViewer
              title="Business Model Document"
              content={businessModelDoc}
            />
            
            <div className="legal-documents-section">
              <h3>Additional Legal Documents</h3>
              {legalDocuments.length > 0 ? (
                legalDocuments.map((doc, index) => (
                  <div key={index} className="legal-document-item">
                    <h4>{doc.title}</h4>
                    <DocumentViewer
                      content={doc.content}
                    />
                  </div>
                ))
              ) : (
                <p>No additional legal documents available</p>
              )}
            </div>
          </div>
        )}
        
        {activeTab === 'compliance' && (
          <div className="compliance-tab">
            <ComplianceChecklist
              items={complianceItems}
              onChange={handleChecklistChange}
            />
          </div>
        )}
        
        {activeTab === 'report' && (
          <div className="report-tab">
            <LegalReportGenerator
              project={project}
              complianceItems={complianceItems}
              legalNotes={legalNotes}
              reviewerName={`${user.firstName} ${user.lastName}`}
            />
          </div>
        )}
      </div>
    </div>
  );
};

export default LegalReview;