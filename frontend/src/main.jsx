
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'

// Global Date Format Override to enforce Day-MONTH-Year (e.g. 7-JAN-2026)
const originalToLocaleDateString = Date.prototype.toLocaleDateString;

Date.prototype.toLocaleDateString = function() {
  const day = this.getDate();
  const month = originalToLocaleDateString.call(this, 'en-US', { month: 'short' }).toUpperCase();
  const year = this.getFullYear();
  return `${day}-${month}-${year}`;
};

Date.prototype.toLocaleString = function() {
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
};

Date.prototype.toLocaleTimeString = function() {
  let hours = this.getHours();
  const minutes = this.getMinutes().toString().padStart(2, '0');
  const ampm = hours >= 12 ? 'PM' : 'AM';
  hours = hours % 12;
  hours = hours ? hours : 12; 
  return `${hours.toString().padStart(2, '0')}:${minutes} ${ampm}`;
};
createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
