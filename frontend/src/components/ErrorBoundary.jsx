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
        <div className="min-h-screen flex flex-col items-center justify-center bg-slate-50 p-6 text-center font-sans">
          <div className="bg-white border border-slate-200 shadow-xl rounded-2xl p-8 max-w-md w-full animate-fade-in">
            <div className="w-12 h-12 rounded-full bg-blue-50 text-blue-600 flex items-center justify-center mx-auto mb-4">
              <span className="material-symbols-outlined text-2xl">refresh</span>
            </div>
            <h2 className="text-xl font-bold text-slate-900 mb-2">Session Navigation Update</h2>
            <p className="text-sm text-slate-500 mb-6 leading-relaxed">
              The page view needs a quick refresh to synchronize your security session.
            </p>
            <button
              onClick={() => {
                this.setState({ hasError: false, error: null });
                window.location.reload();
              }}
              className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-6 rounded-xl transition-all shadow-md shadow-blue-600/20 border-0 cursor-pointer text-sm"
            >
              Refresh Page
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
