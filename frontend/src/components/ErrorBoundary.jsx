import React from 'react';

export class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("Uncaught Error caught by ErrorBoundary:", error, errorInfo);
    // If it's a chunk loading error (common during SPA back-navigation with lazy routes), auto-reload page once
    if (error && (error.name === 'ChunkLoadError' || error.message?.includes('dynamically imported module') || error.message?.includes('Importing a module script failed'))) {
      const hasReloaded = sessionStorage.getItem('chunk_reload_retry');
      if (!hasReloaded) {
        sessionStorage.setItem('chunk_reload_retry', 'true');
        window.location.reload();
      }
    }
  }

  componentDidMount() {
    sessionStorage.removeItem('chunk_reload_retry');
    window.addEventListener('popstate', this.handlePopState);
  }

  componentWillUnmount() {
    window.removeEventListener('popstate', this.handlePopState);
  }

  handlePopState = () => {
    if (this.state.hasError) {
      this.setState({ hasError: false, error: null });
    }
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex flex-col items-center justify-center bg-slate-900 p-6 text-center font-sans">
          <div className="bg-slate-800 border border-slate-700 shadow-2xl rounded-2xl p-8 max-w-md w-full animate-fade-in text-white">
            <div className="w-14 h-14 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20 flex items-center justify-center mx-auto mb-4">
              <span className="material-symbols-outlined text-3xl">warning</span>
            </div>
            
            <h2 className="text-xl font-bold text-slate-100 mb-2">
              Something Went Wrong
            </h2>
            
            <p className="text-sm text-slate-400 mb-6 leading-relaxed">
              Sorry, due to a temporary technical issue, this page could not be displayed properly. Please refresh the page or contact our support team if the problem persists.
            </p>

            <div className="flex flex-col gap-3">
              <button
                onClick={() => {
                  this.setState({ hasError: false, error: null });
                  window.location.reload();
                }}
                className="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-semibold py-3 px-6 rounded-xl transition-all shadow-md shadow-indigo-600/20 border-0 cursor-pointer text-sm flex items-center justify-center gap-2"
              >
                <span className="material-symbols-outlined text-[18px]">refresh</span>
                Refresh Page
              </button>

              <a
                href="mailto:support@larshield.io?subject=LarShield%20System%20Issue%20Report"
                className="w-full bg-slate-700 hover:bg-slate-600 text-slate-200 font-semibold py-2.5 px-6 rounded-xl transition-all border-0 cursor-pointer text-sm no-underline flex items-center justify-center gap-2"
              >
                <span className="material-symbols-outlined text-[18px]">support_agent</span>
                Contact Support Team
              </a>

              <button
                onClick={() => {
                  sessionStorage.clear();
                  localStorage.removeItem('wss_token');
                  localStorage.removeItem('wss_refresh_token');
                  window.location.href = '/login';
                }}
                className="w-full text-slate-400 hover:text-slate-200 text-xs font-medium py-1 transition-all border-0 bg-transparent cursor-pointer mt-1"
              >
                Clear Session & Return to Login
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
