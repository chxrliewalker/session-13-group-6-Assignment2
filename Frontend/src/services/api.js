import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 10000, // 10s timeout
});

/**
 * Health check endpoint
 */
export const checkHealth = async () => {
  try {
    const response = await apiClient.get('/health');
    return response.data;
  } catch (error) {
    console.error('API Health Check Error:', error);
    throw new Error('Unable to connect to backend scanner service.');
  }
};

/**
 * Scan URL for phishing risks
 * @param {string} urlString - Raw URL string to analyze
 */
export const scanUrl = async (urlString) => {
  try {
    const response = await apiClient.post('/predict', { url: urlString });
    return response.data;
  } catch (error) {
    if (error.response) {
      // Backend returned error status code (4xx, 5xx)
      const detail = error.response.data?.detail || error.response.data?.message;
      throw new Error(detail || 'Server encountered an error analyzing the URL.');
    } else if (error.request) {
      // Request made but no response received
      throw new Error('Backend server is offline or unreachable on http://localhost:8000.');
    } else {
      throw new Error(error.message || 'An unexpected error occurred during scan.');
    }
  }
};
