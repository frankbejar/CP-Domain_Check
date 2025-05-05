#!/usr/bin/env python3
"""
Security Assessment Tool

A passive security assessment tool that performs header-based fingerprinting
and DNS configuration analysis, generating professional HTML/PDF reports.
"""

import argparse
import csv
import datetime
import dns.resolver
import dns.exception
import dns.name
import dns.rdtypes
import json
import logging
import os
import pandas as pd
import re
import requests
import socket
import ssl
import sys
import time
import whois
import concurrent.futures
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from concurrent.futures import ThreadPoolExecutor
from jinja2 import Environment, FileSystemLoader
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set
from urllib.parse import urlparse
import weasyprint

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("security_assessment.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("security_assessment")

# Constants
USER_AGENT = "Security-Assessment-Tool/1.0 (Client Security Audit; Contact: your-email@example.com)"
DEFAULT_TIMEOUT = 10  # seconds
SCAN_DELAY = 2  # seconds between domain scans
SSL_PORT = 443

class SecurityAssessment:
    """Main class for security assessment functionality"""
    
    def __init__(self, input_file: str, output_dir: str, client_name: str,
                 max_workers: int = 1, delay: int = SCAN_DELAY, verbose: bool = False):
        """
        Initialize the Security Assessment Tool
        
        Args:
            input_file: Path to CSV file containing domain list
            output_dir: Directory to save the reports
            client_name: Name of the client for the report
            max_workers: Maximum number of concurrent workers
            delay: Delay between requests to the same domain (seconds)
            verbose: Enable verbose logging
        """
        self.input_file = input_file
        self.output_dir = output_dir
        self.client_name = client_name
        self.max_workers = max_workers
        self.delay = delay
        self.verbose = verbose
        self.report_date = datetime.datetime.now()
        
        if verbose:
            logger.setLevel(logging.DEBUG)
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': USER_AGENT,
        })
        
        # Set up DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = DEFAULT_TIMEOUT
        self.resolver.lifetime = DEFAULT_TIMEOUT
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Create images directory for logo if it doesn't exist
        images_dir = os.path.join(output_dir, "reports", "images")
        os.makedirs(images_dir, exist_ok=True)
        
        logger.info(f"Security Assessment initialized for client: {client_name}")
    
    def load_domains(self) -> List[str]:
        """
        Load domains from CSV file
        
        Returns:
            List of domains
        """
        domains = []
        try:
            # Handle different file formats
            if self.input_file.endswith('.csv'):
                df = pd.read_csv(self.input_file)
                # Look for domain column (common variations)
                domain_columns = ['domain', 'Domain', 'title', 'Title', 'url', 'URL']
                for col in domain_columns:
                    if col in df.columns:
                        domains = df[col].tolist()
                        break
                if not domains:
                    # If no standard column found, try to use the first column
                    domains = df.iloc[:, 0].tolist()
            else:
                # Assume it's a simple text file with one domain per line
                with open(self.input_file, 'r') as f:
                    domains = [line.strip() for line in f if line.strip()]
            
            # Clean the domains (remove http://, https://, trailing paths)
            cleaned_domains = []
            for domain in domains:
                if domain and isinstance(domain, str):
                    # Parse URL if it includes http:// or https://
                    if domain.startswith(('http://', 'https://')):
                        parsed = urlparse(domain)
                        domain = parsed.netloc
                    # Remove any trailing path or query
                    domain = domain.split('/')[0].split('?')[0]
                    cleaned_domains.append(domain)
            
            logger.info(f"Loaded {len(cleaned_domains)} domains from {self.input_file}")
            return cleaned_domains
        except Exception as e:
            logger.error(f"Error loading domains from {self.input_file}: {str(e)}")
            raise
    
    def run_assessment(self) -> Dict[str, Any]:
        """
        Run the security assessment
        
        Returns:
            Dictionary containing assessment results
        """
        # Step 1: Load domains
        domains = self.load_domains()
        
        if not domains:
            logger.error("No domains found in input file")
            return {"error": "No domains found in input file"}
        
        # Step 2: Initialize results
        results = {
            "client_name": self.client_name,
            "report_date": self.report_date.strftime("%Y-%m-%d"),
            "domains_assessed": len(domains),
            "domains": {},
            "summary": {
                "critical_issues": 0,
                "high_issues": 0,
                "medium_issues": 0,
                "low_issues": 0,
                "info_issues": 0,
                "total_issues": 0
            }
        }
        
        # Step 3: Analyze domains
        logger.info(f"Analyzing {len(domains)} domains")
        
        # Initialize progress tracking
        total_domains = len(domains)
        processed = 0
        
        # Process domains with thread pool if max_workers > 1
        if self.max_workers > 1:
            domain_results = {}
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_domain = {
                    executor.submit(self.analyze_domain, domain): domain for domain in domains
                }
                
                for future in concurrent.futures.as_completed(future_to_domain):
                    domain = future_to_domain[future]
                    try:
                        result = future.result()
                        domain_results[domain] = result
                        
                        # Update progress
                        processed += 1
                        if processed % 10 == 0 or processed == total_domains:
                            logger.info(f"Progress: {processed}/{total_domains} domains analyzed")
                    except Exception as e:
                        logger.error(f"Error processing domain {domain}: {str(e)}")
                        domain_results[domain] = {
                            "status": "error",
                            "error_message": str(e),
                            "findings": []
                        }
            
            # Update results with domain analysis
            results["domains"] = domain_results
        else:
            # Process domains sequentially
            for domain in domains:
                try:
                    domain_result = self.analyze_domain(domain)
                    results["domains"][domain] = domain_result
                    
                    # Add delay between domains
                    time.sleep(self.delay)
                    
                except Exception as e:
                    logger.error(f"Error processing domain {domain}: {str(e)}")
                    results["domains"][domain] = {
                        "status": "error",
                        "error_message": str(e),
                        "findings": []
                    }
                
                # Update progress
                processed += 1
                if processed % 5 == 0 or processed == total_domains:
                    logger.info(f"Progress: {processed}/{total_domains} domains analyzed")
        
        # Step 4: Calculate summary statistics
        self.calculate_summary(results)
        
        # Step 5: Generate report
        self.generate_report(results)
        
        return results
    
    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """
        Analyze a single domain
        
        Args:
            domain: Domain name to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        logger.debug(f"Analyzing domain: {domain}")
        result = {
            "status": "analyzed",
            "findings": [],
            "dns_info": {},
            "header_info": {},
            "ssl_info": {}
        }
        
        # Step 1: DNS Analysis
        dns_result = self.analyze_dns(domain)
        result["dns_info"] = dns_result["info"]
        result["findings"].extend(dns_result["findings"])
        
        # Step 2: Header Analysis (only if domain resolves)
        if dns_result["info"].get("resolves"):
            header_result = self.analyze_headers(domain)
            result["header_info"] = header_result["info"]
            result["findings"].extend(header_result["findings"])
        
        # Sort findings by severity (critical, high, medium, low, info)
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        result["findings"].sort(key=lambda x: severity_order.get(x["severity"], 5))
        
        return result
    
    def analyze_dns(self, domain: str) -> Dict[str, Any]:
        """
        Analyze DNS configuration
        
        Args:
            domain: Domain name to analyze
            
        Returns:
            Dictionary containing DNS analysis results
        """
        result = {
            "info": {
                "resolves": False,
                "ip_addresses": [],
                "mx_records": [],
                "txt_records": [],
                "name_servers": [],
                "has_spf": False,
                "has_dkim": False,
                "has_dmarc": False,
                "dnssec_enabled": False
            },
            "findings": []
        }
        
        try:
            # Check if domain resolves (A records)
            try:
                a_records = self.resolver.resolve(domain, 'A')
                result["info"]["resolves"] = True
                result["info"]["ip_addresses"] = [record.address for record in a_records]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                result["findings"].append({
                    "title": "Domain Does Not Resolve",
                    "description": f"The domain {domain} does not resolve to any IP address.",
                    "severity": "High",
                    "evidence": "DNS A record query returned no results",
                    "recommendation": "Verify domain registration and DNS configuration"
                })
            
            # Get MX records
            try:
                mx_records = self.resolver.resolve(domain, 'MX')
                result["info"]["mx_records"] = [
                    {"preference": record.preference, "exchange": record.exchange.to_text()} 
                    for record in mx_records
                ]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                # Not having MX records is not necessarily an issue if the domain doesn't use email
                result["info"]["mx_records"] = []
            
            # Get TXT records
            try:
                txt_records = self.resolver.resolve(domain, 'TXT')
                txt_values = [record.strings[0].decode('utf-8') for record in txt_records]
                result["info"]["txt_records"] = txt_values
                
                # Check for SPF
                spf_records = [txt for txt in txt_values if txt.startswith('v=spf1')]
                result["info"]["has_spf"] = len(spf_records) > 0
                
                if len(spf_records) > 1:
                    result["findings"].append({
                        "title": "Multiple SPF Records",
                        "description": f"Multiple SPF records found for {domain}. This can cause email delivery issues.",
                        "severity": "Medium",
                        "evidence": f"Found {len(spf_records)} SPF records: {', '.join(spf_records)}",
                        "recommendation": "Consolidate into a single SPF record"
                    })
                elif len(spf_records) == 0 and result["info"]["mx_records"]:
                    result["findings"].append({
                        "title": "Missing SPF Record",
                        "description": f"No SPF record found for {domain}. This can lead to email spoofing.",
                        "severity": "Medium",
                        "evidence": "No 'v=spf1' prefix found in TXT records",
                        "recommendation": "Implement an SPF record to specify authorized mail servers"
                    })
                elif len(spf_records) == 1:
                    spf_record = spf_records[0]
                    if ' -all' not in spf_record and ' ~all' not in spf_record:
                        result["findings"].append({
                            "title": "Permissive SPF Policy",
                            "description": f"SPF policy for {domain} does not explicitly reject unauthorized senders.",
                            "severity": "Medium",
                            "evidence": f"SPF record: {spf_record}",
                            "recommendation": "Update SPF record to end with '-all' (hard fail) or '~all' (soft fail)"
                        })
                
                # Check for DKIM (indirectly, as actual DKIM records use selectors)
                # We can only check for DKIM policy indicators in TXT records
                dkim_indicators = [txt for txt in txt_values if 'dkim' in txt.lower() or '_domainkey' in domain]
                result["info"]["has_dkim"] = len(dkim_indicators) > 0
                
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                result["info"]["txt_records"] = []
            
            # Check for DMARC
            try:
                dmarc_records = self.resolver.resolve(f"_dmarc.{domain}", 'TXT')
                dmarc_values = [record.strings[0].decode('utf-8') for record in dmarc_records]
                dmarc_records = [txt for txt in dmarc_values if txt.startswith('v=DMARC1')]
                
                result["info"]["has_dmarc"] = len(dmarc_records) > 0
                
                if len(dmarc_records) > 1:
                    result["findings"].append({
                        "title": "Multiple DMARC Records",
                        "description": f"Multiple DMARC records found for {domain}. This can cause email delivery issues.",
                        "severity": "Medium",
                        "evidence": f"Found {len(dmarc_records)} DMARC records",
                        "recommendation": "Consolidate into a single DMARC record"
                    })
                elif len(dmarc_records) == 0 and result["info"]["mx_records"]:
                    result["findings"].append({
                        "title": "Missing DMARC Record",
                        "description": f"No DMARC record found for {domain}. This can lead to email spoofing and phishing.",
                        "severity": "Medium",
                        "evidence": "No DMARC TXT record at _dmarc.{domain}",
                        "recommendation": "Implement a DMARC record to specify email authentication policies"
                    })
                elif len(dmarc_records) == 1:
                    dmarc_record = dmarc_records[0]
                    if 'p=none' in dmarc_record:
                        result["findings"].append({
                            "title": "DMARC Monitor-Only Policy",
                            "description": f"DMARC policy for {domain} is set to 'none', which only monitors without taking action.",
                            "severity": "Low",
                            "evidence": f"DMARC record: {dmarc_record}",
                            "recommendation": "Consider implementing 'p=quarantine' or 'p=reject' after monitoring period"
                        })
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                if result["info"]["mx_records"]:
                    result["findings"].append({
                        "title": "Missing DMARC Record",
                        "description": f"No DMARC record found for {domain}. This can lead to email spoofing and phishing.",
                        "severity": "Medium",
                        "evidence": "Failed to resolve _dmarc.{domain}",
                        "recommendation": "Implement a DMARC record to specify email authentication policies"
                    })
            
            # Get name servers
            try:
                ns_records = self.resolver.resolve(domain, 'NS')
                result["info"]["name_servers"] = [record.target.to_text() for record in ns_records]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                result["info"]["name_servers"] = []
            
            # Check for DNSSEC
            try:
                # Try to get DNSKEY records
                self.resolver.resolve(domain, 'DNSKEY')
                result["info"]["dnssec_enabled"] = True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                result["info"]["dnssec_enabled"] = False
                result["findings"].append({
                    "title": "DNSSEC Not Enabled",
                    "description": f"DNSSEC is not enabled for {domain}. This can allow DNS poisoning attacks.",
                    "severity": "Low",
                    "evidence": "No DNSKEY records found",
                    "recommendation": "Enable DNSSEC to add cryptographic authentication to DNS"
                })
            
            # Check for open DNS resolver (potential for amplification attacks)
            # Note: This is a passive check, we're not actually testing if it's open
            if result["info"]["name_servers"]:
                for ns in result["info"]["name_servers"]:
                    if 'cloudflare' not in ns.lower() and 'google' not in ns.lower() and 'aws' not in ns.lower():
                        result["findings"].append({
                            "title": "Potential Custom DNS Server",
                            "description": f"Domain uses name server {ns} which may need to be checked for misconfiguration.",
                            "severity": "Info",
                            "evidence": f"NS record: {ns}",
                            "recommendation": "Verify that DNS servers are properly configured and not acting as open resolvers"
                        })
            
        except Exception as e:
            logger.error(f"Error analyzing DNS for {domain}: {str(e)}")
            result["findings"].append({
                "title": "DNS Analysis Error",
                "description": f"Error occurred while analyzing DNS for {domain}",
                "severity": "Info",
                "evidence": str(e),
                "recommendation": "Review DNS configuration manually"
            })
        
        return result
    
    def analyze_headers(self, domain: str) -> Dict[str, Any]:
        """
        Analyze HTTP headers
        
        Args:
            domain: Domain name to analyze
            
        Returns:
            Dictionary containing header analysis results
        """
        result = {
            "info": {
                "headers": {},
                "server": None,
                "technologies": [],
                "security_headers": {},
                "cookies": [],
                "https_supported": False,
                "http_version": None
            },
            "findings": []
        }
        
        # First check HTTPS
        https_url = f"https://{domain}"
        try:
            response = self.session.get(https_url, timeout=DEFAULT_TIMEOUT, 
                                        allow_redirects=True, verify=True)
            
            result["info"]["https_supported"] = True
            
            # Extract and analyze headers
            self._process_response_headers(response, result)
            
            # Check SSL/TLS certificate
            ssl_info = self._check_ssl_certificate(domain)
            result["info"]["ssl"] = ssl_info
            
            if ssl_info.get("has_issues"):
                result["findings"].append({
                    "title": "SSL/TLS Certificate Issues",
                    "description": f"Issues detected with SSL/TLS certificate for {domain}",
                    "severity": "Medium",
                    "evidence": ssl_info.get("issues", "Certificate validation failed"),
                    "recommendation": "Review and update SSL/TLS certificate"
                })
            
            # Check HTTP response code
            if response.status_code >= 400:
                result["findings"].append({
                    "title": "HTTP Error Response",
                    "description": f"Site returned HTTP {response.status_code} status code",
                    "severity": "Medium",
                    "evidence": f"HTTP Status: {response.status_code}",
                    "recommendation": "Investigate and fix server response issues"
                })
            
            # Extract HTTP version
            if hasattr(response, 'raw') and hasattr(response.raw, 'version'):
                http_version = response.raw.version
                if http_version == 10:
                    result["info"]["http_version"] = "HTTP/1.0"
                    result["findings"].append({
                        "title": "Outdated HTTP Version",
                        "description": "Site uses HTTP/1.0 which is outdated",
                        "severity": "Low",
                        "evidence": "HTTP/1.0 response",
                        "recommendation": "Upgrade to HTTP/1.1 or HTTP/2"
                    })
                elif http_version == 11:
                    result["info"]["http_version"] = "HTTP/1.1"
                else:
                    result["info"]["http_version"] = f"HTTP/{http_version//10}.{http_version%10}"
            
        except requests.exceptions.SSLError as e:
            result["findings"].append({
                "title": "SSL Certificate Error",
                "description": f"SSL certificate validation failed for {domain}",
                "severity": "High",
                "evidence": str(e),
                "recommendation": "Fix SSL certificate issues"
            })
            
            # Try again with SSL verification disabled (for analysis only)
            try:
                response = self.session.get(https_url, timeout=DEFAULT_TIMEOUT, 
                                            allow_redirects=True, verify=False)
                
                result["info"]["https_supported"] = True
                self._process_response_headers(response, result)
                
            except requests.exceptions.RequestException as e:
                logger.debug(f"HTTPS request failed with verification disabled for {domain}: {str(e)}")
                result["info"]["https_supported"] = False
        
        except requests.exceptions.ConnectionError:
            result["findings"].append({
                "title": "HTTPS Connection Failed",
                "description": f"Could not establish HTTPS connection to {domain}",
                "severity": "High",
                "evidence": "Connection error",
                "recommendation": "Implement HTTPS or fix connection issues"
            })
            
            # Try HTTP if HTTPS failed
            http_url = f"http://{domain}"
            try:
                response = self.session.get(http_url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
                
                result["info"]["https_supported"] = False
                self._process_response_headers(response, result)
                
                result["findings"].append({
                    "title": "HTTPS Not Supported",
                    "description": f"Domain {domain} does not support HTTPS",
                    "severity": "High",
                    "evidence": "HTTP connection succeeded but HTTPS failed",
                    "recommendation": "Implement HTTPS with a valid SSL certificate"
                })
                
            except requests.exceptions.RequestException as e:
                logger.debug(f"HTTP request failed for {domain}: {str(e)}")
                result["findings"].append({
                    "title": "Web Server Unreachable",
                    "description": f"Could not establish connection to {domain} via HTTP or HTTPS",
                    "severity": "Medium",
                    "evidence": str(e),
                    "recommendation": "Verify web server configuration and firewall settings"
                })
        
        except requests.exceptions.RequestException as e:
            logger.debug(f"Request failed for {domain}: {str(e)}")
            result["findings"].append({
                "title": "Web Server Connection Error",
                "description": f"Error occurred while connecting to {domain}",
                "severity": "Medium",
                "evidence": str(e),
                "recommendation": "Verify web server is operational"
            })
        
        return result
    
    def _process_response_headers(self, response: requests.Response, result: Dict[str, Any]) -> None:
        """
        Process HTTP response headers
        
        Args:
            response: HTTP response
            result: Result dictionary to update
        """
        # Store all headers
        headers = dict(response.headers)
        result["info"]["headers"] = headers
        
        # Extract server information
        server = headers.get('Server')
        result["info"]["server"] = server
        
        if server:
            # Check for version disclosure
            version_pattern = r'[0-9]+\.[0-9]+\.[0-9]+'
            if re.search(version_pattern, server):
                result["findings"].append({
                    "title": "Server Version Disclosure",
                    "description": f"Web server version is disclosed in headers",
                    "severity": "Medium",
                    "evidence": f"Server: {server}",
                    "recommendation": "Configure server to hide version information"
                })
        
        # Check for technology headers
        tech_headers = {
            'X-Powered-By': 'Technology disclosure',
            'X-AspNet-Version': 'ASP.NET version disclosure',
            'X-AspNetMvc-Version': 'ASP.NET MVC version disclosure',
            'X-Generator': 'Generator disclosure',
            'X-Drupal-Cache': 'Drupal cache disclosure',
            'X-Varnish': 'Varnish cache disclosure',
            'X-Shopify-Stage': 'Shopify stage disclosure',
            'X-WP-Nonce': 'WordPress nonce disclosure'
        }
        
        technologies = []
        
        for header, description in tech_headers.items():
            if header in headers:
                value = headers[header]
                technologies.append(f"{header}: {value}")
                result["findings"].append({
                    "title": f"{description}",
                    "description": f"Header reveals technology information",
                    "severity": "Low",
                    "evidence": f"{header}: {value}",
                    "recommendation": f"Configure application to hide {header} header"
                })
        
        result["info"]["technologies"] = technologies
        
        # Check security headers
        security_headers = {
            'Strict-Transport-Security': {
                'name': 'HTTP Strict Transport Security (HSTS)',
                'recommended': 'max-age=31536000; includeSubDomains',
                'docs': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'
            },
            'Content-Security-Policy': {
                'name': 'Content Security Policy (CSP)',
                'recommended': 'default-src \'self\'',
                'docs': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'
            },
            'X-Content-Type-Options': {
                'name': 'X-Content-Type-Options',
                'recommended': 'nosniff',
                'docs': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options'
            },
            'X-Frame-Options': {
                'name': 'X-Frame-Options',
                'recommended': 'SAMEORIGIN',
                'docs': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'
            },
            'X-XSS-Protection': {
                'name': 'X-XSS-Protection',
                'recommended': '1; mode=block',
                'docs': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection'
            },
            'Referrer-Policy': {
                'name': 'Referrer Policy',
                'recommended': 'strict-origin-when-cross-origin',
                'docs': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy'
            },
            'Permissions-Policy': {
                'name': 'Permissions Policy',
                'recommended': 'Present (with appropriate restrictions)',
                'docs': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Feature-Policy'
            },
            'Feature-Policy': {
                'name': 'Feature Policy (deprecated)',
                'recommended': 'Present (with appropriate restrictions)',
                'docs': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Feature-Policy'
            }
        }
        
        present_headers = {}
        
        for header, info in security_headers.items():
            if header in headers:
                present_headers[header] = headers[header]
            else:
                result["findings"].append({
                    "title": f"Missing {info['name']} Header",
                    "description": f"The {info['name']} header is not set",
                    "severity": "Medium" if header in ['Strict-Transport-Security', 'Content-Security-Policy'] else "Low",
                    "evidence": f"Header not present in response",
                    "recommendation": f"Add {header}: {info['recommended']} header"
                })
        
        result["info"]["security_headers"] = present_headers
        
        # Check for secure cookies
        cookies = response.cookies
        insecure_cookies = []
        
        for cookie in cookies:
            if not cookie.secure:
                insecure_cookies.append(cookie.name)
                result["findings"].append({
                    "title": "Insecure Cookie",
                    "description": f"Cookie '{cookie.name}' is set without the Secure flag",
                    "severity": "Medium",
                    "evidence": f"Cookie {cookie.name} missing Secure flag",
                    "recommendation": "Set the Secure flag for all cookies"
                })
            
            if not cookie.has_nonstandard_attr('HttpOnly'):
                result["findings"].append({
                    "title": "Cookie Missing HttpOnly Flag",
                    "description": f"Cookie '{cookie.name}' is set without the HttpOnly flag",
                    "severity": "Low",
                    "evidence": f"Cookie {cookie.name} missing HttpOnly flag",
                    "recommendation": "Set the HttpOnly flag for cookies containing sensitive data"
                })
        
        result["info"]["cookies"] = [{"name": c.name, "secure": c.secure, "httponly": c.has_nonstandard_attr('HttpOnly')} for c in cookies]
    
    def _check_ssl_certificate(self, domain: str) -> Dict[str, Any]:
        """
        Check SSL/TLS certificate
        
        Args:
            domain: Domain name
            
        Returns:
            Dictionary containing SSL/TLS certificate information
        """
        result = {
            "has_issues": False,
            "issues": [],
            "issuer": None,
            "subject": None,
            "valid_from": None,
            "valid_until": None,
            "days_remaining": None,
            "version": None
        }
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect to the domain with SSL
            with socket.create_connection((domain, SSL_PORT), timeout=DEFAULT_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    # Get certificate
                    cert_binary = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_binary, default_backend())
                    
                    # Extract certificate information
                    result["issuer"] = cert.issuer.rfc4514_string()
                    result["subject"] = cert.subject.rfc4514_string()
                    result["valid_from"] = cert.not_valid_before.strftime('%Y-%m-%d %H:%M:%S')
                    result["valid_until"] = cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S')
                    
                    # Calculate days remaining
                    days_remaining = (cert.not_valid_after - datetime.datetime.now()).days
                    result["days_remaining"] = days_remaining
                    
                    # Check for expiration
                    if days_remaining < 0:
                        result["has_issues"] = True
                        result["issues"].append(f"Certificate expired {abs(days_remaining)} days ago")
                    elif days_remaining < 30:
                        result["has_issues"] = True
                        result["issues"].append(f"Certificate expires in {days_remaining} days")
                    
                    # Get TLS version
                    result["version"] = ssl.get_protocol_name(ssock.version())
                    if result["version"] in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        result["has_issues"] = True
                        result["issues"].append(f"Outdated protocol: {result['version']}")
            
        except (socket.gaierror, socket.timeout, ssl.SSLError, ConnectionRefusedError) as e:
            result["has_issues"] = True
            result["issues"].append(str(e))
        
        return result
    
    def calculate_summary(self, results: Dict[str, Any]) -> None:
        """
        Calculate summary statistics
        
        Args:
            results: Assessment results to update with summary
        """
        # Reset counters
        results["summary"] = {
            "critical_issues": 0,
            "high_issues": 0,
            "medium_issues": 0,
            "low_issues": 0,
            "info_issues": 0,
            "total_issues": 0,
            "domains_with_issues": 0
        }
        
        # Count issues by severity
        for domain, domain_result in results["domains"].items():
            has_issues = False
            for finding in domain_result.get("findings", []):
                severity = finding.get("severity")
                if severity == "Critical":
                    results["summary"]["critical_issues"] += 1
                    has_issues = True
                elif severity == "High":
                    results["summary"]["high_issues"] += 1
                    has_issues = True
                elif severity == "Medium":
                    results["summary"]["medium_issues"] += 1
                    has_issues = True
                elif severity == "Low":
                    results["summary"]["low_issues"] += 1
                    has_issues = True
                elif severity == "Info":
                    results["summary"]["info_issues"] += 1
            
            if has_issues:
                results["summary"]["domains_with_issues"] += 1
        
        # Calculate total issues
        results["summary"]["total_issues"] = (
            results["summary"]["critical_issues"] +
            results["summary"]["high_issues"] +
            results["summary"]["medium_issues"] +
            results["summary"]["low_issues"] +
            results["summary"]["info_issues"]
        )
    
    def generate_report(self, results: Dict[str, Any]) -> None:
        """
        Generate HTML and PDF reports
        
        Args:
            results: Assessment results
        """
        # Create reports directory if it doesn't exist
        report_dir = os.path.join(self.output_dir, "reports")
        os.makedirs(report_dir, exist_ok=True)
        
        # Create images directory for logo if it doesn't exist
        images_dir = os.path.join(report_dir, "images")
        os.makedirs(images_dir, exist_ok=True)
        
        # Create or check for logo
        logo_path = os.path.join(images_dir, "cyberpools_logo.png")
        if not os.path.exists(logo_path):
            # Create a simple placeholder logo if missing
            self._create_placeholder_logo(logo_path)
        
        # Generate report filename based on client name and date
        client_slug = re.sub(r'[^a-zA-Z0-9]+', '_', self.client_name).lower()
        date_str = self.report_date.strftime("%Y%m%d")
        report_name = f"{client_slug}_security_assessment_{date_str}"
        
        # Generate HTML report
        html_report_path = os.path.join(report_dir, f"{report_name}.html")
        
        try:
            # Set up Jinja2 environment
            env = Environment(loader=FileSystemLoader("templates"))
            template = env.get_template("report_template.html")
            
            # Render template
            html_content = template.render(
                client_name=self.client_name,
                report_date=self.report_date.strftime("%B %d, %Y"),
                summary=results["summary"],
                domains=results["domains"],
                small_report=len(results["domains"]) <= 2
            )
            
            # Write HTML file
            with open(html_report_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            
            logger.info(f"HTML report generated: {html_report_path}")
            
            # Generate PDF report
            pdf_report_path = os.path.join(report_dir, f"{report_name}.pdf")
            
            try:
                # Use WeasyPrint to convert HTML to PDF with improved styling
                html = weasyprint.HTML(string=html_content, base_url=os.path.abspath(report_dir))
                
                # Define PDF-specific CSS
                pdf_css = weasyprint.CSS(string='''
                    @page {
                        size: letter;
                        margin: 1.5cm;
                        @top-center {
                            content: "Security Assessment Report";
                            font-size: 9pt;
                        }
                        @bottom-right {
                            content: "Page " counter(page) " of " counter(pages);
                            font-size: 9pt;
                        }
                    }
                    
                    body {
                        font-family: sans-serif;
                        font-size: 10pt;
                        line-height: 1.4;
                    }
                    
                    h1, h2, h3, h4 {
                        margin-top: 1em;
                        margin-bottom: 0.5em;
                        font-weight: bold;
                        color: #000 !important;
                    }
                    
                    /* Keep these elements together */
                    .domain-section,
                    .finding-list li,
                    .recommendation-section,
                    table,
                    .no-break {
                        page-break-inside: avoid !important;
                    }
                    
                    /* Ensure no blank pages */
                    .page-break {
                        page-break-before: always;
                        clear: both;
                        break-after: avoid;
                    }
                    
                    /* Replace box-shadow with borders for PDF */
                    .summary-card, .domain-section, table {
                        box-shadow: none !important;
                        border: 1px solid #ddd !important;
                    }
                    
                    /* More compact layout for PDF */
                    .container {
                        padding: 0;
                        margin: 0;
                    }
                    
                    p {
                        margin-bottom: 8px;
                    }
                    
                    .finding-list li {
                        margin-bottom: 8px;
                        padding: 8px;
                    }
                    
                    .header {
                        background-color: #fff !important;
                        color: #000 !important;
                        padding: 10px 0;
                        margin-bottom: 10px;
                    }
                    
                    /* Severity colors */
                    .severity-Critical { background-color: #ffcccc; }
                    .severity-High { background-color: #ffddcc; }
                    .severity-Medium { background-color: #ffffcc; }
                    .severity-Low { background-color: #e6ffcc; }
                    .severity-Info { background-color: #e6f2ff; }
                    
                    /* Adjust table styling */
                    table {
                        border-collapse: collapse;
                        width: 100%;
                        margin: 0.5em 0;
                    }
                    
                    th, td {
                        border: 1px solid #ddd;
                        padding: 6px;
                        text-align: left;
                    }
                    
                    th {
                        background-color: #f2f2f2;
                    }
                    
                    /* Brand footer */
                    .cyberpools-brand {
                        background-color: #fff !important;
                        color: #000 !important;
                        border: 1px solid #000;
                    }
                    
                    .cyberpools-brand a {
                        color: #000 !important;
                    }
                ''')
                
                # Add conditional page breaks based on report size
                if len(results["domains"]) <= 2:
                    # For small reports, don't force page breaks
                    html.write_pdf(pdf_report_path, stylesheets=[pdf_css])
                else:
                    # For larger reports, keep normal page breaks
                    html.write_pdf(pdf_report_path, stylesheets=[pdf_css])
                
                logger.info(f"PDF report generated: {pdf_report_path}")
                
            except Exception as e:
                logger.error(f"Error generating PDF report: {str(e)}")
                
        except Exception as e:
            logger.error(f"Error generating HTML report: {str(e)}")
    
    def _create_placeholder_logo(self, logo_path: str) -> None:
        """
        Create a simple placeholder logo if the real logo is missing
        
        Args:
            logo_path: Path to save the logo
        """
        try:
            # Simple SVG logo as base64 data
            logo_svg = '''
            <svg xmlns="http://www.w3.org/2000/svg" width="150" height="50" viewBox="0 0 150 50">
                <circle cx="25" cy="25" r="20" fill="#2c5282" />
                <text x="25" y="30" font-family="Arial" font-size="14" fill="white" text-anchor="middle">&lt;/&gt;</text>
                <text x="85" y="32" font-family="Arial" font-size="30" font-weight="bold" fill="#2c5282" text-anchor="middle">CP</text>
                <text x="75" y="45" font-family="Arial" font-size="10" fill="#2c5282" text-anchor="middle">CYBERPOOLS.ORG</text>
            </svg>
            '''
            
            # Save as PNG using cairosvg if available
            try:
                import cairosvg
                cairosvg.svg2png(bytestring=logo_svg.encode('utf-8'), write_to=logo_path)
                logger.info(f"Created placeholder logo at {logo_path}")
            except ImportError:
                # If cairosvg not available, try a simple approach
                with open(logo_path, 'wb') as f:
                    # Minimal PNG as fallback (1x1 transparent pixel)
                    minimal_png = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82'
                    f.write(minimal_png)
                logger.info(f"Created minimal placeholder logo at {logo_path}")
        except Exception as e:
            logger.error(f"Error creating placeholder logo: {str(e)}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Security Assessment Tool")
    parser.add_argument("input", help="Input file containing domain list (CSV or TXT)")
    parser.add_argument("--output", help="Output directory for reports", default="./reports")
    parser.add_argument("--client", help="Client name for the report", default="Client")
    parser.add_argument("--workers", type=int, default=1, help="Maximum number of concurrent workers")
    parser.add_argument("--delay", type=int, default=SCAN_DELAY, help="Delay between requests (seconds)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    try:
        assessment = SecurityAssessment(
            input_file=args.input,
            output_dir=args.output,
            client_name=args.client,
            max_workers=args.workers,
            delay=args.delay,
            verbose=args.verbose
        )
        
        results = assessment.run_assessment()
        
        # Print summary
        print("\nAssessment Summary:")
        print(f"Client: {args.client}")
        print(f"Domains assessed: {results['domains_assessed']}")
        print(f"Total issues found: {results['summary']['total_issues']}")
        print(f"  Critical: {results['summary']['critical_issues']}")
        print(f"  High: {results['summary']['high_issues']}")
        print(f"  Medium: {results['summary']['medium_issues']}")
        print(f"  Low: {results['summary']['low_issues']}")
        print(f"  Info: {results['summary']['info_issues']}")
        print(f"\nReports saved to: {os.path.join(args.output, 'reports')}")
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()