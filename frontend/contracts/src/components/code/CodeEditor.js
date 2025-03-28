// File: frontend/src/components/code/CodeEditor.js
import React, { useEffect, useRef } from 'react';
import * as monaco from 'monaco-editor';

const CodeEditor = ({ language, value, onChange, readOnly = false }) => {
  const editorRef = useRef(null);
  const containerRef = useRef(null);

  useEffect(() => {
    if (containerRef.current) {
      editorRef.current = monaco.editor.create(containerRef.current, {
        value,
        language,
        theme: 'vs-dark',
        automaticLayout: true,
        minimap: { enabled: true },
        scrollBeyondLastLine: false,
        fontSize: 14,
        fontFamily: 'Fira Code, Consolas, monospace',
        tabSize: 2,
        readOnly
      });

      // Add change event handler
      editorRef.current.onDidChangeModelContent(() => {
        if (onChange) {
          onChange(editorRef.current.getValue());
        }
      });

      // Cleanup
      return () => {
        editorRef.current.dispose();
      };
    }
  }, []);

  // Update editor value if prop changes
  useEffect(() => {
    if (editorRef.current) {
      if (editorRef.current.getValue() !== value) {
        editorRef.current.setValue(value);
      }
    }
  }, [value]);

  // Update editor language if prop changes
  useEffect(() => {
    if (editorRef.current) {
      monaco.editor.setModelLanguage(editorRef.current.getModel(), language);
    }
  }, [language]);

  return (
    <div className="code-editor" ref={containerRef} style={{ height: '500px', width: '100%' }} />
  );
};

export default CodeEditor;