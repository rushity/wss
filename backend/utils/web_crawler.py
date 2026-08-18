import uuid
import hashlib
import hmac
import secrets
import base64
import subprocess
from typing import *
import os
import sys
import re
import json
import time
import urllib3
import requests
import socket
import logging
import threading
import concurrent.futures
import ipaddress
import ssl
from urllib.parse import urlparse, urljoin, urlencode, quote
from collections import defaultdict
from bs4 import BeautifulSoup
from datetime import datetime, timezone


# Suppress insecure request warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WebCrawler:
    def __init__(self, target_url, max_depth=2, delay=0.5, auth_headers=None, log_fn=None,
                 exclude_paths=None, max_urls=None):
        self.target_url = target_url
        self.max_depth = max_depth
        self.delay = delay
        self.auth_headers = auth_headers or {}
        self.log_fn = log_fn
        self.exclude_paths = exclude_paths or []
        self.max_urls = max_urls or max(50, max_depth * 25)
        self.visited_urls = set()
        self.discovered_urls = []
        self.discovered_forms = []
        self.domain = urlparse(target_url).netloc

    def log(self, level, message):
        """Helper to write to the scanner logger if provided, else console."""
        if self.log_fn:
            self.log_fn(level, message)
        else:
            print(f"[{level}] {message}")

    def is_valid_url(self, url):
        """Check if URL is valid and belongs to the target domain"""
        parsed = urlparse(url)
        return parsed.netloc == self.domain and parsed.scheme in ['http', 'https']

    def is_excluded(self, url):
        """Skip URLs matching user-defined path exclusions."""
        if not self.exclude_paths:
            return False
        path = urlparse(url).path or "/"
        for pattern in self.exclude_paths:
            if not pattern:
                continue
            normalized = pattern if pattern.startswith("/") else f"/{pattern}"
            if path.startswith(normalized) or normalized in path:
                return True
        return False
    
    def get_all_links(self, url, soup):
        """Extract all links from page"""
        links = set()
        for tag in soup.find_all('a', href=True):
            link = urljoin(url, tag['href'])
            link = link.split('#')[0]
            if self.is_valid_url(link):
                links.add(link)
        return links
    
    def extract_forms(self, url, soup):
        """Extract all forms from page"""
        forms_data = []
        forms = soup.find_all('form')
        
        for form in forms:
            form_details = {
                'url': url,
                'action': urljoin(url, form.get('action', '')),
                'method': form.get('method', 'get').lower(),
                'inputs': []
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_type = input_tag.get('type', 'text')
                input_name = input_tag.get('name', '')
                if input_name:
                    form_details['inputs'].append({
                        'type': input_type,
                        'name': input_name,
                        'value': input_tag.get('value', '')
                    })
            
            if form_details['inputs']:
                forms_data.append(form_details)
        
        return forms_data
    
    def crawl(self, url, depth=0):
        """Recursively crawl website"""
        if depth > self.max_depth or url in self.visited_urls:
            return
        if self.is_excluded(url):
            self.log("INFO", f"[Crawler] Skipping excluded path: {url}")
            return
        if len(self.visited_urls) >= self.max_urls:
            self.log("WARNING", f"[Crawler] Max URL limit ({self.max_urls}) reached — stopping crawl")
            return
        
        self.log("INFO", f"[Crawler] Crawling depth {depth}: {url}")
        self.visited_urls.add(url)
        
        try:
            # Inject auth_headers for authenticated crawling
            headers = {"User-Agent": "LarShield/2.0 Crawler"}
            headers.update(self.auth_headers)
            
            response = requests.get(url, headers=headers, timeout=10, allow_redirects=True, verify=False)
            self.discovered_urls.append({
                'url': url,
                'status': response.status_code,
                'depth': depth
            })
            
            if response.status_code == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.content, 'html.parser')
                
                forms = self.extract_forms(url, soup)
                self.discovered_forms.extend(forms)
                if forms:
                    self.log("SUCCESS", f"[Crawler] Found {len(forms)} form(s) on {url}")
                
                links = self.get_all_links(url, soup)
                for link in links:
                    if link not in self.visited_urls:
                        time.sleep(self.delay)
                        self.crawl(link, depth + 1)
                        
        except Exception as e:
            self.log("WARNING", f"[Crawler] Error crawling {url}: {str(e)}")
    
    def start(self):
        """Start crawling from target URL"""
        exclusion_note = f", Exclusions: {len(self.exclude_paths)}" if self.exclude_paths else ""
        self.log("INFO",
                 f"[Crawler] Starting Web Crawler (Target: {self.target_url}, "
                 f"Max Depth: {self.max_depth}, Max URLs: {self.max_urls}{exclusion_note})")
        self.crawl(self.target_url)
        self.log("SUCCESS", f"[Crawler] Crawl complete. Discovered {len(self.discovered_urls)} URLs and {len(self.discovered_forms)} forms.")
        return {
            'urls': self.discovered_urls,
            'forms': self.discovered_forms
        }

