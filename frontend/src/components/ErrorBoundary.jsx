import React from 'react';

export class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, showDetails: false };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("Uncaught Error caught by ErrorBoundary:", error, errorInfo);
    // If it's a chunk loading error (common after new deployments or SPA lazy route updates), auto-reload page once
    const isChunkError = error && (
      error.name === 'ChunkLoadError' ||
      error.message?.includes('dynamically imported module') ||
      error.message?.includes('Importing a module script failed') ||
      error.message?.includes('Failed to fetch dynamically imported module') ||
      error.message?.includes('Failed to load module script')
    );

    if (isChunkError) {
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
      this.setState({ hasError: false, error: null, showDetails: false });
    }
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex flex-col items-center justify-center bg-[#f8fafc] p-6 text-center font-sans">
          <div className="bg-white border border-slate-200/80 shadow-2xl rounded-3xl p-8 max-w-lg w-full animate-fade-in text-slate-900">
            {/* Warning Icon Badge */}
            <div className="w-16 h-16 rounded-2xl bg-amber-500/10 text-amber-600 border border-amber-500/20 flex items-center justify-center mx-auto mb-5 shadow-xs">
              <span className="material-symbols-outlined text-4xl">warning</span>
            </div>
            
            <h2 className="text-2xl font-black text-slate-900 mb-2 tracking-tight">
              Something Went Wrong
            </h2>
            
            <p className="text-sm text-slate-600 mb-6 leading-relaxed font-medium">
              Sorry, due to a temporary technical issue or standard network update, this page could not be displayed properly. Please refresh the page or contact our support team.
            </p>

            {/* Optional Collapsible Technical Details */}
            {this.state.error?.message && (
              <div className="mb-6 text-left">
                <button
                  onClick={() => this.setState(prev => ({ showDetails: !prev.showDetails }))}
                  className="text-[12px] font-bold text-slate-500 hover:text-primary transition-colors flex items-center gap-1 bg-transparent border-0 cursor-pointer p-0 mb-2 mx-auto"
                >
                  <span className="material-symbols-outlined text-[16px]">
                    {this.state.showDetails ? 'expand_less' : 'expand_more'}
                  </span>
                  {this.state.showDetails ? 'Hide Error Details' : 'View Error Details'}
                </button>

                {this.state.showDetails && (
                  <div className="bg-slate-900 text-slate-200 p-3.5 rounded-xl font-mono text-[11px] overflow-x-auto max-h-36 border border-slate-800 break-all select-all leading-relaxed shadow-inner">
                    <span className="text-red-400 font-bold">Error:</span> {this.state.error.toString()}
                  </div>
                )}
              </div>
            )}

            {/* Action Buttons */}
            <div className="flex flex-col gap-3">
              <button
                onClick={() => {
                  this.setState({ hasError: false, error: null, showDetails: false });
                  window.location.reload();
                }}
                className="w-full bg-primary hover:brightness-110 text-white font-bold py-3.5 px-6 rounded-xl transition-all shadow-md shadow-primary/20 border-0 cursor-pointer text-sm flex items-center justify-center gap-2 active:scale-[0.99]"
              >
                <span className="material-symbols-outlined text-[20px]">refresh</span>
                Refresh Page
              </button>

              <a
                href="mailto:support@larshield.io?subject=LarShield%20System%20Issue%20Report"
                className="w-full bg-slate-100 hover:bg-slate-200 text-slate-700 font-bold py-3 px-6 rounded-xl transition-all border border-slate-200/80 cursor-pointer text-sm no-underline flex items-center justify-center gap-2 active:scale-[0.99]"
              >
                <span className="material-symbols-outlined text-[20px]">support_agent</span>
                Contact Support Team
              </a>

              <button
                onClick={() => {
                  sessionStorage.clear();
                  localStorage.removeItem('wss_token');
                  localStorage.removeItem('wss_refresh_token');
                  localStorage.removeItem('superAdminActiveTab');
                  localStorage.removeItem('supportEngineerActiveTab');
                  window.location.href = '/login';
                }}
                className="w-full text-slate-500 hover:text-red-600 text-xs font-bold py-1.5 transition-colors border-0 bg-transparent cursor-pointer mt-1"
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
