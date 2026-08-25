import os
import sys
from dotenv import load_dotenv

# Ensure environment variables are loaded
load_dotenv()

# Insert the backend module into the python path so its internal absolute imports work
sys.path.insert(0, os.path.abspath('backend_structured'))

# Import the application factory from our partitioned architecture
from backend_structured import create_app

# Initialize the Flask application
app = create_app()

# ---------------------------------------------------------------------------
# Serve the built React frontend (HF Spaces / single-container mode)
# In development the Vite dev-server proxies /api/ to Flask instead.
# ---------------------------------------------------------------------------
from flask import send_from_directory, abort

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'frontend', 'dist')


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_react(path):
    """Serve React SPA. Static assets go to dist/, everything else → index.html."""
    # Never intercept API, uploads, or socket.io requests
    if path.startswith('api/') or path.startswith('uploads/') or path.startswith('socket.io'):
        abort(404)
    if path and os.path.exists(os.path.join(FRONTEND_DIR, path)):
        res = send_from_directory(FRONTEND_DIR, path)
    else:
        res = send_from_directory(FRONTEND_DIR, 'index.html')

    res.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    res.headers['Pragma'] = 'no-cache'
    res.headers['Expires'] = '0'
    return res


if __name__ == '__main__':
    from backend_structured.extensions import socketio
    port = int(os.getenv('PORT', 7860))
    socketio.run(app, host='0.0.0.0', port=port, debug=True)
