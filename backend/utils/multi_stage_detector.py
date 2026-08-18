"""
multi_stage_detector.py — Multi-Stage Vulnerability Detection Framework
=======================================================================
Advanced detection framework implementing 3-stage detection:
- Stage 1: Passive reconnaissance (headers, cookies, responses)
- Stage 2: Active probing with low-impact payloads
- Stage 3: Confirmation with high-impact payloads
"""

import time
import threading
from typing import Callable, Optional, Dict, List, Tuple
from enum import Enum

class DetectionStage(Enum):
    """Detection stages for vulnerability confirmation."""
    PASSIVE = 1
    ACTIVE_PROBE = 2
    CONFIRMATION = 3

class ConfidenceLevel(Enum):
    """Confidence levels for vulnerability findings."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CONFIRMED = "Confirmed"

class MultiStageDetector:
    """
    Multi-stage vulnerability detection framework.
    
    Implements progressive testing strategy:
    1. Passive analysis - no active payloads
    2. Active probing - low-impact, non-destructive payloads
    3. Confirmation - high-impact payloads only if stage 2 succeeds
    """
    
    def __init__(self, scan_id: str, target: str):
        self.scan_id = scan_id
        self.target = target
        self.stage_results = {
            DetectionStage.PASSIVE: [],
            DetectionStage.ACTIVE_PROBE: [],
            DetectionStage.CONFIRMATION: []
        }
        self.confidence = ConfidenceLevel.LOW
        self._lock = threading.Lock()
    
    def execute_stage(
        self,
        stage: DetectionStage,
        test_func: Callable,
        payloads: List[str],
        max_tests: int = 10
    ) -> List[Dict]:
        """
        Execute a detection stage with given payloads.
        
        Args:
            stage: Detection stage to execute
            test_func: Function to test each payload (returns dict with result)
            payloads: List of payloads to test
            max_tests: Maximum number of payloads to test
            
        Returns:
            List of successful results from this stage
        """
        results = []
        tested = 0
        
        for payload in payloads[:max_tests]:
            try:
                result = test_func(payload)
                if result and result.get('success', False):
                    with self._lock:
                        self.stage_results[stage].append(result)
                        results.append(result)
                        self._update_confidence(stage)
                    break  # Stop on first success
                tested += 1
            except Exception as e:
                continue
        
        return results
    
    def _update_confidence(self, stage: DetectionStage) -> None:
        """Update confidence level based on stage success."""
        if stage == DetectionStage.PASSIVE:
            self.confidence = ConfidenceLevel.LOW
        elif stage == DetectionStage.ACTIVE_PROBE:
            self.confidence = ConfidenceLevel.MEDIUM
        elif stage == DetectionStage.CONFIRMATION:
            self.confidence = ConfidenceLevel.HIGH
    
    def get_confidence(self) -> str:
        """Get current confidence level."""
        return self.confidence.value
    
    def get_stage_results(self, stage: Optional[DetectionStage] = None) -> Dict:
        """Get results from specific stage or all stages."""
        if stage:
            return self.stage_results.get(stage, [])
        return self.stage_results
    
    def has_findings(self) -> bool:
        """Check if any stage produced findings."""
        return any(len(results) > 0 for results in self.stage_results.values())
    
    def reset(self) -> None:
        """Reset detector state."""
        with self._lock:
            self.stage_results = {
                DetectionStage.PASSIVE: [],
                DetectionStage.ACTIVE_PROBE: [],
                DetectionStage.CONFIRMATION: []
            }
            self.confidence = ConfidenceLevel.LOW


class PassiveAnalyzer:
    """Passive reconnaissance without active payloads."""
    
    @staticmethod
    def analyze_headers(headers: Dict[str, str]) -> List[Dict]:
        """Analyze HTTP headers for security issues."""
        findings = []
        
        # Check for security headers
        security_headers = [
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Content-Security-Policy',
            'Strict-Transport-Security',
            'Referrer-Policy'
        ]
        
        missing_headers = [h for h in security_headers if h not in headers]
        if missing_headers:
            findings.append({
                'type': 'missing_security_headers',
                'headers': missing_headers,
                'severity': 'Medium'
            })
        
        # Check for information disclosure
        info_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
        for header in info_headers:
            if header in headers:
                findings.append({
                    'type': 'information_disclosure',
                    'header': header,
                    'value': headers[header],
                    'severity': 'Low'
                })
        
        return findings
    
    @staticmethod
    def analyze_cookies(cookies: Dict[str, str]) -> List[Dict]:
        """Analyze cookies for security issues."""
        findings = []
        
        for name, value in cookies.items():
            # Check for secure flag (can't detect from value alone, but check for patterns)
            if 'session' in name.lower() or 'auth' in name.lower():
                findings.append({
                    'type': 'session_cookie',
                    'name': name,
                    'severity': 'Low'
                })
        
        return findings
    
    @staticmethod
    def analyze_response_body(body: str) -> List[Dict]:
        """Analyze response body for potential vulnerabilities."""
        findings = []
        
        # Check for common error messages
        error_patterns = [
            'mysql',
            'postgresql',
            'oracle',
            'mssql',
            'sqlite',
            'stack trace',
            'exception',
            'error',
            'warning'
        ]
        
        body_lower = body.lower()
        for pattern in error_patterns:
            if pattern in body_lower:
                findings.append({
                    'type': 'error_disclosure',
                    'pattern': pattern,
                    'severity': 'Low'
                })
                break
        
        # Check for comments with sensitive info
        import re
        comment_patterns = [
            r'<!--.*?password.*?-->',
            r'<!--.*?api.*?key.*?-->',
            r'<!--.*?secret.*?-->',
            r'//.*?password.*?',
            r'//.*?api.*?key.*?',
        ]
        
        for pattern in comment_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                findings.append({
                    'type': 'sensitive_info_in_comments',
                    'severity': 'Medium'
                })
                break
        
        return findings


class ActiveProber:
    """Active probing with low-impact payloads."""
    
    def __init__(self, scan_id: str, request_func: Callable):
        self.scan_id = scan_id
        self.request_func = request_func
    
    def probe_parameter(
        self,
        url: str,
        param: str,
        payloads: List[str],
        check_func: Callable
    ) -> Optional[Dict]:
        """
        Probe a parameter with low-impact payloads.
        
        Args:
            url: Target URL
            param: Parameter name to test
            payloads: List of payloads to test
            check_func: Function to check response for vulnerability indicators
            
        Returns:
            Result dict if vulnerability found, None otherwise
        """
        from urllib.parse import urlencode, urlparse, urlunparse
        
        parsed = urlparse(url)
        base = urlunparse(parsed._replace(query="", fragment=""))
        
        for payload in payloads[:5]:  # Limit to 5 payloads for probing
            try:
                test_url = f"{base}?{urlencode({param: payload})}"
                body, status = self.request_func(test_url)
                
                if body and check_func(body, status):
                    return {
                        'success': True,
                        'url': test_url,
                        'param': param,
                        'payload': payload,
                        'status': status,
                        'stage': 'active_probe'
                    }
            except Exception:
                continue
        
        return None


class ConfirmationTester:
    """Confirmation testing with high-impact payloads."""
    
    def __init__(self, scan_id: str, request_func: Callable):
        self.scan_id = scan_id
        self.request_func = request_func
    
    def confirm_vulnerability(
        self,
        url: str,
        param: str,
        payloads: List[Tuple[str, float]],
        check_func: Callable,
        timeout: float = 10.0
    ) -> Optional[Dict]:
        """
        Confirm vulnerability with high-impact payloads.
        
        Args:
            url: Target URL
            param: Parameter name to test
            payloads: List of (payload, expected_delay) tuples
            check_func: Function to check response for confirmation
            timeout: Maximum time to wait for response
            
        Returns:
            Result dict if vulnerability confirmed, None otherwise
        """
        from urllib.parse import urlencode, urlparse, urlunparse
        
        parsed = urlparse(url)
        base = urlunparse(parsed._replace(query="", fragment=""))
        
        for payload, expected_delay in payloads[:3]:  # Limit to 3 payloads for confirmation
            try:
                test_url = f"{base}?{urlencode({param: payload})}"
                start = time.time()
                body, status = self.request_func(test_url, timeout=int(timeout + 2))
                elapsed = time.time() - start
                
                if body and check_func(body, status, elapsed, expected_delay):
                    return {
                        'success': True,
                        'url': test_url,
                        'param': param,
                        'payload': payload,
                        'status': status,
                        'elapsed_time': elapsed,
                        'stage': 'confirmation'
                    }
            except Exception:
                continue
        
        return None


def create_multi_stage_test(
    scan_id: str,
    target: str,
    request_func: Callable,
    passive_analyzer: Optional[PassiveAnalyzer] = None,
    active_prober: Optional[ActiveProber] = None,
    confirmation_tester: Optional[ConfirmationTester] = None
) -> MultiStageDetector:
    """
    Factory function to create a multi-stage detector with all components.
    
    Args:
        scan_id: Scan identifier
        target: Target URL
        request_func: Function to make HTTP requests
        passive_analyzer: Optional custom passive analyzer
        active_prober: Optional custom active prober
        confirmation_tester: Optional custom confirmation tester
        
    Returns:
        Configured MultiStageDetector instance
    """
    detector = MultiStageDetector(scan_id, target)
    
    if passive_analyzer is None:
        passive_analyzer = PassiveAnalyzer()
    
    if active_prober is None:
        active_prober = ActiveProber(scan_id, request_func)
    
    if confirmation_tester is None:
        confirmation_tester = ConfirmationTester(scan_id, request_func)
    
    # Store components for later use
    detector.passive_analyzer = passive_analyzer
    detector.active_prober = active_prober
    detector.confirmation_tester = confirmation_tester
    
    return detector
