"""
Firebase Cloud Storage helper for LarShield / SentinelScan.

Uploads organization logos and scan report PDFs to Firebase Storage
and returns public/signed download URLs.

Env vars required:
    FIREBASE_CREDENTIALS  — path to serviceAccountKey.json OR base64-encoded JSON OR JSON string
    FIREBASE_STORAGE_BUCKET — e.g. your-project.appspot.com or gs://your-project.appspot.com
"""

import os
import io
import base64
import json
import logging
import urllib.parse
from datetime import timedelta
from typing import Optional, Union, Any

try:
    import firebase_admin
    from firebase_admin import credentials, storage
    HAS_FIREBASE = True
except ImportError:
    firebase_admin = None  # type: ignore
    credentials = None     # type: ignore
    storage = None         # type: ignore
    HAS_FIREBASE = False

logger = logging.getLogger(__name__)

# Firebase references — lazily initialized
_app: Any = None
_bucket: Any = None
_initialized: bool = False


def _get_credentials_path() -> Optional[str]:
    """Retrieve Firebase credentials path/string from environment."""
    creds = os.getenv("FIREBASE_CREDENTIALS")
    return creds.strip() if creds else None


def _get_bucket_name() -> Optional[str]:
    """Retrieve and sanitize Firebase storage bucket name from environment."""
    raw_bucket = os.getenv("FIREBASE_STORAGE_BUCKET")
    if not raw_bucket:
        return None
    # Sanitize prefix (gs:// or https://) and trailing slashes
    clean_bucket = raw_bucket.strip()
    for prefix in ("gs://", "https://", "http://"):
        if clean_bucket.lower().startswith(prefix):
            clean_bucket = clean_bucket[len(prefix):]
    return clean_bucket.split('/')[0].strip()


def init_firebase(force_reinit: bool = False) -> bool:
    """
    Initialize the Firebase Admin SDK with service-account credentials.
    Safe to call multiple times — only initializes once unless force_reinit=True.
    Returns True if initialization succeeded, False otherwise.
    """
    global _app, _bucket, _initialized

    if _initialized and not force_reinit and _bucket is not None:
        return True

    if not HAS_FIREBASE or firebase_admin is None or credentials is None or storage is None:
        logger.warning(
            "[Firebase] firebase_admin package is not installed. "
            "File uploads will fall back to local disk."
        )
        _initialized = True
        return False

    creds_path = _get_credentials_path()
    bucket_name = _get_bucket_name()

    if not creds_path or not bucket_name:
        logger.warning(
            "[Firebase] FIREBASE_CREDENTIALS or FIREBASE_STORAGE_BUCKET not set. "
            "File uploads will fall back to local disk."
        )
        _initialized = True
        return False

    try:
        # Parse credentials from file, raw JSON string, or base64 JSON
        cred = None
        if os.path.isfile(creds_path):
            cred = credentials.Certificate(creds_path)
        elif creds_path.startswith('{'):
            cred = credentials.Certificate(json.loads(creds_path))
        else:
            try:
                # Attempt base64 decode
                creds_json = base64.b64decode(creds_path).decode("utf-8")
                creds_dict = json.loads(creds_json)
                cred = credentials.Certificate(creds_dict)
            except Exception:
                # Fallback to raw JSON load
                creds_dict = json.loads(creds_path)
                cred = credentials.Certificate(creds_dict)

        # Initialize or retrieve Firebase Admin app instance
        if not firebase_admin._apps:
            _app = firebase_admin.initialize_app(cred, {"storageBucket": bucket_name})
        else:
            try:
                _app = firebase_admin.get_app()
            except ValueError:
                _app = firebase_admin.initialize_app(cred, {"storageBucket": bucket_name})

        # Always bind to the specific bucket name requested
        if _app:
            _bucket = storage.bucket(name=bucket_name, app=_app)
        else:
            _bucket = storage.bucket(name=bucket_name)

        _initialized = True
        logger.info(f"[Firebase] Initialized successfully. Bucket: {bucket_name}")
        return True

    except Exception as e:
        logger.error(f"[Firebase] Initialization failed: {e}")
        _initialized = True
        return False


def is_available() -> bool:
    """
    Check if Firebase Storage is ready to use.
    Retries initialization if environment variables become available later.
    """
    global _initialized
    if not _initialized or _bucket is None:
        # Retry initialization if credentials are now present in environment
        if _get_credentials_path() and _get_bucket_name():
            return init_firebase(force_reinit=True)
        if not _initialized:
            init_firebase()
    return _bucket is not None


def _build_fallback_url(destination_blob: str) -> str:
    """Generate public media download URL for Uniform Bucket-Level Access buckets."""
    clean_blob = destination_blob.lstrip('/')
    encoded_blob = urllib.parse.quote(clean_blob, safe='')
    bucket_name = _bucket.name if _bucket and hasattr(_bucket, 'name') else _get_bucket_name() or "storage"
    return f"https://firebasestorage.googleapis.com/v0/b/{bucket_name}/o/{encoded_blob}?alt=media"


def _get_public_or_fallback_url(blob: Any, destination_blob: str) -> str:
    """Extract public URL or fallback to media download link."""
    url = None
    try:
        blob.make_public()
        url = getattr(blob, 'public_url', None)
    except Exception as pub_err:
        logger.debug(f"[Firebase] make_public skipped (Uniform Bucket Access active): {pub_err}")

    if not url:
        url = _build_fallback_url(destination_blob)
    return url


def upload_bytes(
    data: bytes,
    content_type: str,
    destination_blob: str,
) -> Optional[str]:
    """
    Upload raw bytes to Firebase Storage.

    Args:
        data: File content as bytes.
        content_type: MIME type (e.g. "image/png", "application/pdf").
        destination_blob: Full blob path (e.g. "logos/org123/logo.png").

    Returns:
        Public download URL on success, None on failure.
    """
    if not is_available():
        logger.warning("[Firebase] Storage not available. Upload skipped.")
        return None

    if not data:
        logger.warning(f"[Firebase] Empty data bytes provided for {destination_blob}.")
        return None

    try:
        blob = _bucket.blob(destination_blob)
        blob.upload_from_string(data, content_type=content_type)
        url = _get_public_or_fallback_url(blob, destination_blob)
        logger.info(f"[Firebase] Uploaded {destination_blob} ({len(data)} bytes)")
        return url

    except Exception as e:
        logger.error(f"[Firebase] Upload failed for {destination_blob}: {e}")
        return None


def upload_fileobj(
    fileobj: Union[io.BytesIO, io.BufferedIOBase, Any],
    content_type: str,
    destination_blob: str,
) -> Optional[str]:
    """
    Upload a file-like object to Firebase Storage.

    Args:
        fileobj: A BytesIO or file stream with the file data.
        content_type: MIME type.
        destination_blob: Full blob path.

    Returns:
        Public download URL on success, None on failure.
    """
    if not is_available():
        return None

    try:
        blob = _bucket.blob(destination_blob)
        try:
            fileobj.seek(0)
        except Exception:
            pass

        blob.upload_from_file(fileobj, content_type=content_type)
        url = _get_public_or_fallback_url(blob, destination_blob)
        logger.info(f"[Firebase] Uploaded fileobj to {destination_blob}")
        return url

    except Exception as e:
        logger.error(f"[Firebase] Upload failed for {destination_blob}: {e}")
        return None


def download_bytes(destination_blob: str) -> Optional[bytes]:
    """
    Download raw bytes from Firebase Storage.

    Args:
        destination_blob: Full blob path.

    Returns:
        File contents as bytes on success, None on failure.
    """
    if not is_available():
        return None

    try:
        blob = _bucket.blob(destination_blob)
        if not blob.exists():
            logger.warning(f"[Firebase] Blob not found: {destination_blob}")
            return None
        data = blob.download_as_bytes()
        logger.info(f"[Firebase] Downloaded {destination_blob} ({len(data)} bytes)")
        return data
    except Exception as e:
        logger.error(f"[Firebase] Download failed for {destination_blob}: {e}")
        return None


def blob_exists(destination_blob: str) -> bool:
    """Check if a file exists in Firebase Storage."""
    if not is_available():
        return False
    try:
        blob = _bucket.blob(destination_blob)
        return bool(blob.exists())
    except Exception as e:
        logger.error(f"[Firebase] Exists check failed for {destination_blob}: {e}")
        return False


def delete_blob(destination_blob: str) -> bool:
    """Delete a file from Firebase Storage."""
    if not is_available():
        return False

    try:
        blob = _bucket.blob(destination_blob)
        if blob.exists():
            blob.delete()
            logger.info(f"[Firebase] Deleted {destination_blob}")
            return True
        logger.warning(f"[Firebase] Delete skipped, blob does not exist: {destination_blob}")
        return False

    except Exception as e:
        logger.error(f"[Firebase] Delete failed for {destination_blob}: {e}")
        return False


def get_blob_url(blob_name: str) -> Optional[str]:
    """Return the public URL for an existing blob (without uploading)."""
    if not is_available():
        return None
    try:
        blob = _bucket.blob(blob_name)
        if hasattr(blob, 'public_url') and blob.public_url:
            return blob.public_url
        return _build_fallback_url(blob_name)
    except Exception:
        return _build_fallback_url(blob_name)


def get_signed_url(destination_blob: str, expiration_minutes: int = 60) -> Optional[str]:
    """
    Generate a temporary signed download URL for private files.

    Args:
        destination_blob: Full blob path.
        expiration_minutes: Expiration time in minutes (default: 60).

    Returns:
        Signed URL string on success, None on failure.
    """
    if not is_available():
        return None
    try:
        blob = _bucket.blob(destination_blob)
        signed_url = blob.generate_signed_url(
            expiration=timedelta(minutes=expiration_minutes),
            method='GET'
        )
        return signed_url
    except Exception as e:
        logger.error(f"[Firebase] Generating signed URL failed for {destination_blob}: {e}")
        return None
