// File: frontend/src/pages/developer/CodeReview.js
import React, { useState, useEffect, useContext } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { AuthContext } from '../../context/AuthContext';
import { NotificationContext } from '../../context/NotificationContext';
import CodeEditor from '../../components/code/CodeEditor';
import CodeDiff from '../../components/code/CodeDiff';
import IssueList from '../../components/review/IssueList';
import IssueForm from '../../components/review/IssueForm';
import api from '../../services/api';
import '../../styles/CodeReview.css';

const CodeReview = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const { user } = useContext(AuthContext);
  const { addNotification } = useContext(NotificationContext);
  
  const [project, setProject] = useState(null);
  const [codeFiles, setCodeFiles] = useState([]);
  const [currentFile, setCurrentFile] = useState(0);
  const [issues, setIssues] = useState([]);
  const [loading, setLoading] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [showDiff, setShowDiff] = useState(false);
  const [originalCode, setOriginalCode] = useState('');
  const [modifiedCode, setModifiedCode] = useState('');
  
  useEffect(() => {
    const fetchProject = async () => {
      try {
        const res = await api.get(`/api/projects/${id}`);
        setProject(res.data);
        setCodeFiles(res.data.files);
        
        // Fetch existing issues for this project
        const issuesRes = await api.get(`/api/reviews/project/${id}`);
        setIssues(issuesRes.data);
      } catch (err) {
        console.error('Error fetching project:', err);
        addNotification('Failed to load project data', 'error');
        navigate('/review-dashboard');
      } finally {
        setLoading(false);
      }
    };
    
    fetchProject();
  }, [id, navigate, addNotification]);
  
  const handleFileChange = (index) => {
    setCurrentFile(index);
    setShowDiff(false);
    setOriginalCode('');
    setModifiedCode('');
  };
  
  const handleCodeChange = (value) => {
    if (!showDiff) {
      const updatedFiles = [...codeFiles];
      updatedFiles[currentFile].content = value;
      setCodeFiles(updatedFiles);
    } else {
      setModifiedCode(value);
    }
  };
  
  const toggleDiffView = () => {
    if (!showDiff) {
      setOriginalCode(project.files[currentFile].content);
      setModifiedCode(codeFiles[currentFile].content);
    }
    setShowDiff(!showDiff);
  };
  
  const handleAddIssue = async (issue) => {
    try {
      const newIssue = {
        ...issue,
        projectId: id,
        fileIndex: currentFile,
        fileName: codeFiles[currentFile].name,
        reviewerId: user._id,
        reviewerName: `${user.firstName} ${user.lastName}`,
        status: 'open',
        createdAt: new Date()
      };
      
      const res = await api.post('/api/reviews', newIssue);
      setIssues([...issues, res.data]);
      addNotification('Issue added successfully', 'success');
    } catch (err) {
      console.error('Error adding issue:', err);
      addNotification('Failed to add issue', 'error');
    }
  };
  
  const handleResolveIssue = async (issueId) => {
    try {
      await api.put(`/api/reviews/${issueId}`, { status: 'resolved' });
      
      // Update local state
      setIssues(
        issues.map(issue => 
          issue._id === issueId ? { ...issue, status: 'resolved' } : issue
        )
      );
      
      addNotification('Issue marked as resolved', 'success');
    } catch (err) {
      console.error('Error resolving issue:', err);
      addNotification('Failed to resolve issue', 'error');
    }
  };
  
  const handleSubmitReview = async () => {
    setIsSubmitting(true);
    
    try {
      // Submit code changes if any
      if (JSON.stringify(project.files) !== JSON.stringify(codeFiles)) {
        await api.put(`/api/projects/${id}/files`, { files: codeFiles });
      }
      
      // Mark review as completed
      await api.post(`/api/reviews/complete/${id}`, {
        reviewerId: user._id,
        comments: 'Review completed'
      });
      
      addNotification('Review submitted successfully', 'success');
      navigate('/review-dashboard');
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
    <div className="code-review-container">
      <div className="review-header">
        <h1>{project.title} - Code Review</h1>
        <div className="review-actions">
          <button 
            className="toggle-diff-btn" 
            onClick={toggleDiffView}
          >
            {showDiff ? 'Exit Diff View' : 'Show Diff'}
          </button>
          <button 
            className="submit-review-btn" 
            onClick={handleSubmitReview}
            disabled={isSubmitting}
          >
            {isSubmitting ? 'Submitting...' : 'Submit Review'}
          </button>
        </div>
      </div>
      
      <div className="review-grid">
        <div className="project-info-section">
          <h2>Project Information</h2>
          <div className="project-info">
            <p><strong>Description:</strong> {project.description}</p>
            <p><strong>Submitted by:</strong> {project.userFullName}</p>
            <p><strong>Tags:</strong> {project.tags.join(', ')}</p>
            <p><strong>Submitted:</strong> {new Date(project.createdAt).toLocaleDateString()}</p>
          </div>
          
          <div className="issue-section">
            <h3>Issues</h3>
            <IssueList 
              issues={issues.filter(issue => issue.fileIndex === currentFile)} 
              onResolve={handleResolveIssue}
              currentUserId={user._id}
            />
            <IssueForm onAddIssue={handleAddIssue} />
          </div>
        </div>
        
        <div className="code-section">
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
          
          {showDiff ? (
            <CodeDiff 
              original={originalCode} 
              modified={modifiedCode} 
              language={codeFiles[currentFile].language}
              onModifiedChange={handleCodeChange}
            />
          ) : (
            <CodeEditor
              language={codeFiles[currentFile].language}
              value={codeFiles[currentFile].content}
              onChange={handleCodeChange}
            />
          )}
        </div>
      </div>
    </div>
  );
};

export default CodeReview;