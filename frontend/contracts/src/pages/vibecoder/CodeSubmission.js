// File: frontend/src/pages/vibecoder/CodeSubmission.js
import React, { useState, useEffect, useContext } from 'react';
import { useNavigate } from 'react-router-dom';
import { AuthContext } from '../../context/AuthContext';
import { NotificationContext } from '../../context/NotificationContext';
import CodeEditor from '../../components/code/CodeEditor';
import VersionControl from '../../components/code/VersionControl';
import ProjectDetailsForm from '../../components/forms/ProjectDetailsForm';
import api from '../../services/api';
import '../../styles/CodeSubmission.css';

const CodeSubmission = () => {
  const navigate = useNavigate();
  const { user } = useContext(AuthContext);
  const { addNotification } = useContext(NotificationContext);
  
  const [projectDetails, setProjectDetails] = useState({
    title: '',
    description: '',
    tags: [],
    businessModel: '',
    revenueModel: '',
    targetMarket: '',
    isPrivate: false
  });
  
  const [codeFiles, setCodeFiles] = useState([
    { name: 'index.js', language: 'javascript', content: '// Add your code here' }
  ]);
  
  const [currentFile, setCurrentFile] = useState(0);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errors, setErrors] = useState({});
  
  const handleProjectChange = (e) => {
    const { name, value, type, checked } = e.target;
    setProjectDetails({
      ...projectDetails,
      [name]: type === 'checkbox' ? checked : value
    });
  };
  
  const handleTagsChange = (tags) => {
    setProjectDetails({
      ...projectDetails,
      tags
    });
  };
  
  const addNewFile = () => {
    const fileName = prompt('Enter file name with extension:');
    if (!fileName) return;
    
    const extension = fileName.split('.').pop().toLowerCase();
    let language = 'plaintext';
    
    // Determine language based on file extension
    if (['js', 'jsx'].includes(extension)) language = 'javascript';
    else if (['ts', 'tsx'].includes(extension)) language = 'typescript';
    else if (extension === 'html') language = 'html';
    else if (extension === 'css') language = 'css';
    else if (extension === 'py') language = 'python';
    else if (['java', 'kt'].includes(extension)) language = 'java';
    else if (['c', 'cpp', 'h', 'hpp'].includes(extension)) language = 'cpp';
    
    setCodeFiles([
      ...codeFiles,
      { name: fileName, language, content: '' }
    ]);
    
    setCurrentFile(codeFiles.length);
  };
  
  const handleCodeChange = (value) => {
    const updatedFiles = [...codeFiles];
    updatedFiles[currentFile].content = value;
    setCodeFiles(updatedFiles);
  };
  
  const validateForm = () => {
    const newErrors = {};
    
    if (!projectDetails.title.trim()) {
      newErrors.title = 'Project title is required';
    }
    
    if (!projectDetails.description.trim()) {
      newErrors.description = 'Project description is required';
    }
    
    if (projectDetails.tags.length === 0) {
      newErrors.tags = 'At least one tag is required';
    }
    
    // Check if at least one file has content
    const hasCode = codeFiles.some(file => file.content.trim().length > 0);
    if (!hasCode) {
      newErrors.code = 'At least one file must contain code';
    }
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) {
      addNotification('Please fix the errors before submitting', 'error');
      return;
    }
    
    setIsSubmitting(true);
    
    try {
      const formData = {
        ...projectDetails,
        files: codeFiles,
        userId: user._id
      };
      
      const response = await api.post('/api/projects', formData);
      
      addNotification('Project submitted successfully!', 'success');
      navigate(`/projects/${response.data._id}`);
    } catch (error) {
      console.error('Submission error:', error);
      addNotification(
        error.response?.data?.message || 'Failed to submit project',
        'error'
      );
    } finally {
      setIsSubmitting(false);
    }
  };
  
  return (
    <div className="code-submission-container">
      <h1>Submit New Project</h1>
      
      <div className="submission-grid">
        <div className="project-details-section">
          <h2>Project Details</h2>
          <ProjectDetailsForm
            projectDetails={projectDetails}
            handleProjectChange={handleProjectChange}
            handleTagsChange={handleTagsChange}
            errors={errors}
          />
        </div>
        
        <div className="code-editor-section">
          <div className="editor-header">
            <h2>Code Editor</h2>
            <div className="file-tabs">
              {codeFiles.map((file, index) => (
                <button
                  key={index}
                  className={`file-tab ${currentFile === index ? 'active' : ''}`}
                  onClick={() => setCurrentFile(index)}
                >
                  {file.name}
                </button>
              ))}
              <button className="add-file-btn" onClick={addNewFile}>
                + Add File
              </button>
            </div>
          </div>
          
          <CodeEditor
            language={codeFiles[currentFile].language}
            value={codeFiles[currentFile].content}
            onChange={handleCodeChange}
          />
          
          {errors.code && <div className="error-message">{errors.code}</div>}
          
          <VersionControl />
        </div>
      </div>
      
      <div className="submission-actions">
        <button
          className="submit-btn"
          onClick={handleSubmit}
          disabled={isSubmitting}
        >
          {isSubmitting ? 'Submitting...' : 'Submit Project'}
        </button>
        <button
          className="cancel-btn"
          onClick={() => navigate('/my-projects')}
          disabled={isSubmitting}
        >
          Cancel
        </button>
      </div>
    </div>
  );
};

export default CodeSubmission;