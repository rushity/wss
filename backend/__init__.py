# pyright: reportGeneralTypeIssues=false, reportAttributeAccessIssue=false
from flask import Flask
from .config import Config, _is_redis_running
from .extensions import db, celery, socketio, limiter, cache
from flask_cors import CORS

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize extensions
    db.init_app(app)
    from .extensions import migrate
    migrate.init_app(app, db) # type: ignore
    socketio.init_app(app, cors_allowed_origins="*") # type: ignore
    app.socketio = socketio  # type: ignore
    
    # Configure Caching dynamically based on Redis availability
    redis_url = app.config.get('CELERY_BROKER_URL', 'redis://localhost:6379/0')
    if _is_redis_running(redis_url):
        app.config['CACHE_TYPE'] = 'RedisCache'
        app.config['CACHE_REDIS_URL'] = redis_url
    else:
        app.config['CACHE_TYPE'] = 'SimpleCache'
    
    cache.init_app(app)

    # Initialize Firebase Cloud Storage (for logos, PDFs, and file uploads)
    try:
        from backend.utils.firebase_storage import init_firebase
    except ImportError:
        from utils.firebase_storage import init_firebase
    init_firebase()

    # Optional Celery config update
    celery.conf.update(
        broker_url=redis_url,
        result_backend=app.config.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
    )

    CORS(app, resources={r"/api/*": {"origins": "*"}}) # type: ignore

    with app.app_context():
        # Import routes to register blueprints
        from .routes import api_bp, auth_bp, scans_bp, vuln_bp, reports_bp
        app.register_blueprint(api_bp)
        app.register_blueprint(auth_bp, url_prefix='/api/auth')
        app.register_blueprint(scans_bp, url_prefix='/api/scans')
        app.register_blueprint(vuln_bp, url_prefix='/api/vulnerabilities')
        app.register_blueprint(reports_bp, url_prefix='/api/reports')
        
        # Create tables
        db.create_all()

        # Seed superadmin user (created once, never overwritten)
        from .models import User
        import os
        if not User.query.filter_by(email='superadmin@gmail.com').first():
            sa = User(email='superadmin@gmail.com', role='super_admin', org_id=None)
            sa.set_password(os.getenv('SUPERADMIN_PASSWORD', 'larshield2025'))
            db.session.add(sa)
            db.session.commit()
            print("[System] Superadmin user seeded (superadmin@gmail.com)")
        
        # Cleanup stale scans that were truly abandoned/interrupted (> 10 mins old)
        from .models import Scan
        from datetime import datetime, timezone, timedelta
        try:
            ten_mins_ago = datetime.now(timezone.utc) - timedelta(minutes=10)
            stale_scans = Scan.query.filter(
                Scan.status.in_(['queued', 'scanning']),
                (Scan.started_at < ten_mins_ago) | (Scan.started_at == None)
            ).all()
            for scan in stale_scans:
                scan.status = 'failed'
            if stale_scans:
                db.session.commit()
                print(f"[System] Marked {len(stale_scans)} stale/interrupted scans as failed on startup.")
        except Exception as e:
            print(f"[System] Failed to clean up stale scans: {e}")

    return app
