"""
Firebase Cloud Storage helper for SentinelScan.

Uploads organization logos and scan report PDFs to Firebase Storage
and returns public/signed download URLs.

Env vars required:
    FIREBASE_CREDENTIALS  — path to serviceAccountKey.json OR base64-encoded JSON
    FIREBASE_STORAGE_BUCKET — e.g. your-project.appspot.com
"""

import os
import io
import base64
import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Firebase references — lazily initialized
_app = None
_bucket = None
_initialized = False


def _get_credentials_path() -> Optional[str]:
    return os.getenv("FIREBASE_CREDENTIALS")


def _get_bucket_name() -> Optional[str]:
    return os.getenv("FIREBASE_STORAGE_BUCKET")


def init_firebase() -> bool:
    """
    Initialize the Firebase Admin SDK with service-account credentials.
    Safe to call multiple times — only initializes once.
    Returns True if initialization succeeded, False otherwise.
    """
    global _app, _bucket, _initialized

    if _initialized:
        return _bucket is not None

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
        import firebase_admin
        from firebase_admin import credentials, storage

        if not firebase_admin._apps:
            # Support both file path, base64-encoded JSON, and direct JSON string
            if os.path.isfile(creds_path):
                cred = credentials.Certificate(creds_path)
            else:
                try:
                    creds_json = base64.b64decode(creds_path).decode("utf-8")
                    creds_dict = json.loads(creds_json)
                except Exception:
                    creds_dict = json.loads(creds_path)
                cred = credentials.Certificate(creds_dict)

            _app = firebase_admin.initialize_app(cred, {"storageBucket": bucket_name})

        _bucket = storage.bucket()
        _initialized = True
        logger.info(f"[Firebase] Initialized. Bucket: {bucket_name}")
        return True

    except Exception as e:
        logger.error(f"[Firebase] Initialization failed: {e}")
        _initialized = True
        return False


def is_available() -> bool:
    """Check if Firebase Storage is ready to use."""
    if not _initialized:
        init_firebase()
    return _bucket is not None


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
        logger.error("[Firebase] Storage not available. Upload skipped.")
        return None

    try:
        blob = _bucket.blob(destination_blob)
        blob.upload_from_string(data, content_type=content_type)
        try:
            blob.make_public()
            url = blob.public_url
        except Exception as pub_err:
            logger.warning(f"[Firebase] make_public failed (Uniform Bucket-Level Access active), generating public media URL: {pub_err}")
            import urllib.parse
            encoded_blob = urllib.parse.quote(destination_blob, safe='')
            bucket_name = _bucket.name if _bucket else "storage"
            url = f"https://firebasestorage.googleapis.com/v0/b/{bucket_name}/o/{encoded_blob}?alt=media"

        logger.info(f"[Firebase] Uploaded {destination_blob} ({len(data)} bytes)")
        return url

    except Exception as e:
        logger.error(f"[Firebase] Upload failed for {destination_blob}: {e}")
        return None


def upload_fileobj(
    fileobj: io.BytesIO,
    content_type: str,
    destination_blob: str,
) -> Optional[str]:
    """
    Upload a file-like object to Firebase Storage.

    Args:
        fileobj: A BytesIO (or similar) with the file data.
        content_type: MIME type.
        destination_blob: Full blob path.

    Returns:
        Public download URL on success, None on failure.
    """
    if not is_available():
        return None

    try:
        blob = _bucket.blob(destination_blob)
        fileobj.seek(0)
        blob.upload_from_file(fileobj, content_type=content_type)
        try:
            blob.make_public()
            url = blob.public_url
        except Exception as pub_err:
            logger.warning(f"[Firebase] make_public failed (Uniform Bucket-Level Access active), generating public media URL: {pub_err}")
            import urllib.parse
            encoded_blob = urllib.parse.quote(destination_blob, safe='')
            bucket_name = _bucket.name if _bucket else "storage"
            url = f"https://firebasestorage.googleapis.com/v0/b/{bucket_name}/o/{encoded_blob}?alt=media"

        logger.info(f"[Firebase] Uploaded {destination_blob}")
        return url

    except Exception as e:
        logger.error(f"[Firebase] Upload failed for {destination_blob}: {e}")
        return None


def delete_blob(destination_blob: str) -> bool:
    """Delete a file from Firebase Storage."""
    if not is_available():
        return False

    try:
        blob = _bucket.blob(destination_blob)
        blob.delete()
        logger.info(f"[Firebase] Deleted {destination_blob}")
        return True

    except Exception as e:
        logger.error(f"[Firebase] Delete failed for {destination_blob}: {e}")
        return False


def get_blob_url(blob_name: str) -> Optional[str]:
    """Return the public URL for an existing blob (without uploading)."""
    if not is_available():
        return None
    try:
        blob = _bucket.blob(blob_name)
        return blob.public_url
    except Exception:
        return None
