import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'

// Safe Global Date Format Overrides
const originalToLocaleDateString = Date.prototype.toLocaleDateString;

Date.prototype.toLocaleDateString = function() {
  if (isNaN(this.getTime())) return 'N/A';
  try {
    const day = this.getDate();
    const month = originalToLocaleDateString.call(this, 'en-US', { month: 'short' }).toUpperCase();
    const year = this.getFullYear();
    return `${day}-${month}-${year}`;
  } catch {
    return 'N/A';
  }
};

Date.prototype.toLocaleString = function() {
  if (isNaN(this.getTime())) return 'N/A';
  try {
    const day = this.getDate();
    const month = originalToLocaleDateString.call(this, 'en-US', { month: 'short' }).toUpperCase();
    const year = this.getFullYear();
    
    let hours = this.getHours();
    const minutes = this.getMinutes().toString().padStart(2, '0');
    const ampm = hours >= 12 ? 'PM' : 'AM';
    hours = hours % 12;
    hours = hours ? hours : 12; 
    const strTime = `${hours.toString().padStart(2, '0')}:${minutes} ${ampm}`;
    
    return `${day}-${month}-${year} ${strTime}`;
  } catch {
    return 'N/A';
  }
};

Date.prototype.toLocaleTimeString = function() {
  if (isNaN(this.getTime())) return 'N/A';
  try {
    let hours = this.getHours();
    const minutes = this.getMinutes().toString().padStart(2, '0');
    const ampm = hours >= 12 ? 'PM' : 'AM';
    hours = hours % 12;
    hours = hours ? hours : 12; 
    return `${hours.toString().padStart(2, '0')}:${minutes} ${ampm}`;
  } catch {
    return 'N/A';
  }
};

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
