"""
SolarWinds Log Analyzer & Resolution Tool
Analyzes SolarWinds logs to identify issues and find resolutions from the internet
"""

import os
import re
import json
import logging
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple
from pathlib import Path
from collections import defaultdict
import glob

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('solarwinds_log_analyzer.log'),
        logging.StreamHandler()
    ]
)

class LogPathManager:
    """Manages all SolarWinds log file locations"""
    
    LOG_LOCATIONS = {
        'configuration_wizard': r'C:\ProgramData\SolarWinds\Logs\Orion\ConfigurationWizard',
        'information_service': r'C:\ProgramData\SolarWinds\InformationService\v3.0',
        'orion_web': r'C:\ProgramData\SolarWinds\Logs\Orion\orionweb.log',
        'business_layer': r'C:\ProgramData\SolarWinds\Logs\Orion\BusinessLayerHost.log',
        'sql_debug': r'C:\ProgramData\SolarWinds\Logs\Orion\swdebugmaintenance.log',
        'collector': r'C:\ProgramData\SolarWinds\Collector\Logs',
        'job_engine': r'C:\ProgramData\SolarWinds\JobEngine.v2\Logs',
        'high_availability': r'C:\ProgramData\SolarWinds\Logs\HighAvailability',
        'swis': r'C:\ProgramData\SolarWinds\InformationService',
        'apm': r'C:\ProgramData\SolarWinds\Logs\APM\APMServiceControl',
        'permission_checker': r'C:\Program Files\SolarWinds\Orion\OrionPermissionChecker'
    }
    
    def get_all_log_files(self, hours_back: int = 24) -> Dict[str, List[str]]:
        """Get all log files modified within specified hours"""
        cutoff_time = datetime.now() - timedelta(hours=hours_back)
        log_files = {}
        
        for category, path in self.LOG_LOCATIONS.items():
            files = []
            try:
                if os.path.isfile(path):
                    if datetime.fromtimestamp(os.path.getmtime(path)) > cutoff_time:
                        files.append(path)
                elif os.path.isdir(path):
                    for pattern in ['*.log', '*.txt']:
                        for file_path in glob.glob(os.path.join(path, '**', pattern), recursive=True):
                            if datetime.fromtimestamp(os.path.getmtime(file_path)) > cutoff_time:
                                files.append(file_path)
                
                if files:
                    log_files[category] = files
                    logging.info(f"Found {len(files)} log file(s) for {category}")
            except Exception as e:
                logging.warning(f"Could not access {category} logs: {e}")
        
        return log_files


class LogParser:
    """Parses SolarWinds log files and extracts issues"""
    
    # Error patterns to identify in logs
    ERROR_PATTERNS = {
        'sql_error': [
            r'(?i)(SQL Server|database).*?(error|exception|failed|timeout)',
            r'(?i)deadlock|lock timeout|connection.*failed',
            r'(?i)cannot open database|login failed',
            r'(?i)tempdb.*full|transaction log.*full'
        ],
        'connection_error': [
            r'(?i)connection.*(?:refused|timeout|closed|failed)',
            r'(?i)unable to connect|cannot connect',
            r'(?i)network.*unreachable|host.*unreachable'
        ],
        'authentication_error': [
            r'(?i)authentication.*failed|unauthorized',
            r'(?i)access.*denied|permission.*denied',
            r'(?i)invalid.*credentials|login.*failed',
            r'(?i)401|403 forbidden'
        ],
        'memory_error': [
            r'(?i)out of memory|outofmemory',
            r'(?i)insufficient.*memory|memory.*exhausted',
            r'(?i)heap.*overflow|stackoverflow'
        ],
        'service_error': [
            r'(?i)service.*(?:stopped|failed|crashed)',
            r'(?i)unable to start|failed to start',
            r'(?i)service.*not running|service.*unavailable'
        ],
        'polling_error': [
            r'(?i)polling.*failed|poll.*error',
            r'(?i)SNMP.*(?:timeout|error|failed)',
            r'(?i)WMI.*(?:error|failed|timeout)',
            r'(?i)node.*(?:unreachable|not responding)'
        ],
        'license_error': [
            r'(?i)license.*(?:expired|invalid|exceeded)',
            r'(?i)evaluation.*expired|trial.*expired'
        ],
        'web_error': [
            r'(?i)HTTP.*(?:500|502|503|504)',
            r'(?i)web.*(?:error|exception|failed)',
            r'(?i)IIS.*error|application.*error'
        ],
        'job_error': [
            r'(?i)job.*failed|scheduled.*failed',
            r'(?i)task.*error|execution.*failed'
        ],
        'ha_error': [
            r'(?i)failover.*failed|high availability.*error',
            r'(?i)replication.*failed|sync.*failed'
        ],
        'certificate_error': [
            r'(?i)certificate.*(?:expired|invalid|untrusted)',
            r'(?i)SSL.*error|TLS.*error'
        ],
        'timeout_error': [
            r'(?i)timeout|timed out',
            r'(?i)request.*timeout|operation.*timeout'
        ],
        'configuration_error': [
            r'(?i)configuration.*(?:error|invalid|missing)',
            r'(?i)misconfigured|invalid.*setting'
        ]
    }
    
    def __init__(self):
        self.compiled_patterns = {}
        for category, patterns in self.ERROR_PATTERNS.items():
            self.compiled_patterns[category] = [re.compile(p) for p in patterns]
    
    def parse_log_file(self, file_path: str, max_lines: int = 10000) -> List[Dict]:
        """Parse a single log file and extract issues"""
        issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                line_num = 0
                for line in f:
                    line_num += 1
                    if line_num > max_lines:
                        break
                    
                    # Check for error indicators
                    if any(indicator in line.lower() for indicator in ['error', 'exception', 'failed', 'critical', 'fatal']):
                        issue = self._analyze_line(line, file_path, line_num)
                        if issue:
                            issues.append(issue)
        
        except Exception as e:
            logging.error(f"Error parsing {file_path}: {e}")
        
        return issues
    
    def _analyze_line(self, line: str, file_path: str, line_num: int) -> Dict:
        """Analyze a log line and categorize the issue"""
        # Extract timestamp if present
        timestamp = self._extract_timestamp(line)
        
        # Categorize the error
        category = 'unknown'
        for cat, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(line):
                    category = cat
                    break
            if category != 'unknown':
                break
        
        # Extract exception details
        exception_type = self._extract_exception(line)
        
        # Get context
        severity = self._determine_severity(line)
        
        return {
            'file': os.path.basename(file_path),
            'full_path': file_path,
            'line_number': line_num,
            'timestamp': timestamp,
            'category': category,
            'severity': severity,
            'message': line.strip(),
            'exception_type': exception_type
        }
    
    def _extract_timestamp(self, line: str) -> str:
        """Extract timestamp from log line"""
        timestamp_patterns = [
            r'\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}',
            r'\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}',
            r'\d{2}-\d{2}-\d{4}\s+\d{2}:\d{2}:\d{2}'
        ]
        
        for pattern in timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(0)
        return 'Unknown'
    
    def _extract_exception(self, line: str) -> str:
        """Extract exception type from log line"""
        exception_pattern = r'(?:Exception|Error):\s*([A-Za-z\.]+(?:Exception|Error))'
        match = re.search(exception_pattern, line)
        return match.group(1) if match else None
    
    def _determine_severity(self, line: str) -> str:
        """Determine severity level"""
        line_lower = line.lower()
        if any(word in line_lower for word in ['critical', 'fatal', 'severe']):
            return 'CRITICAL'
        elif 'error' in line_lower:
            return 'ERROR'
        elif 'warning' in line_lower:
            return 'WARNING'
        return 'INFO'


class IssueAggregator:
    """Aggregates and deduplicates similar issues"""
    
    def aggregate_issues(self, issues: List[Dict]) -> List[Dict]:
        """Group similar issues together"""
        grouped = defaultdict(list)
        
        for issue in issues:
            # Skip INFO level issues
            if issue['severity'] == 'INFO':
                continue
                
            # Create a key based on category and similar message content
            key = (issue['category'], self._normalize_message(issue['message']))
            grouped[key].append(issue)
        
        aggregated = []
        for (category, normalized_msg), issue_list in grouped.items():
            # Sort by timestamp (most recent first)
            issue_list.sort(key=lambda x: x['timestamp'], reverse=True)
            
            aggregated.append({
                'category': category,
                'count': len(issue_list),
                'first_occurrence': issue_list[-1]['timestamp'],
                'last_occurrence': issue_list[0]['timestamp'],
                'severity': max((i['severity'] for i in issue_list), 
                              key=lambda x: ['WARNING', 'ERROR', 'CRITICAL'].index(x)),
                'sample_message': issue_list[0]['message'][:500],
                'affected_files': list(set(i['file'] for i in issue_list)),
                'exception_type': issue_list[0].get('exception_type'),
                'all_occurrences': issue_list[:10]  # Keep top 10 occurrences
            })
        
        # Sort by severity and count
        severity_order = {'CRITICAL': 0, 'ERROR': 1, 'WARNING': 2}
        aggregated.sort(key=lambda x: (severity_order[x['severity']], -x['count']))
        
        return aggregated
    
    def _normalize_message(self, message: str) -> str:
        """Normalize message for grouping"""
        # Remove timestamps, IDs, and numbers
        normalized = re.sub(r'\d{4}-\d{2}-\d{2}', '', message)
        normalized = re.sub(r'\d{2}:\d{2}:\d{2}', '', normalized)
        normalized = re.sub(r'\b\d+\b', 'N', normalized)
        normalized = re.sub(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', 'GUID', normalized, flags=re.IGNORECASE)
        return normalized[:100]


class ResolutionFinder:
    """Finds resolutions for identified issues"""
    
    def __init__(self):
        self.kb_base_url = "https://support.solarwinds.com"
        self.success_center_url = "https://solarwindscore.my.site.com/SuccessCenter"
        self.thwack_url = "https://thwack.solarwinds.com"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def search_solarwinds_kb(self, error_message: str, category: str) -> List[Dict]:
        """Search SolarWinds KB, Success Center, Thwack and general web for relevant articles"""
        all_kb_articles = []
        
        try:
            # Extract key terms from error message
            search_terms = self._extract_search_terms(error_message, category)
            
            if not search_terms or len(search_terms.strip()) < 3:
                logging.warning("Search terms too short or empty, skipping KB search")
                return []
            
            logging.info(f"Searching for: {search_terms}")
            
            # 1. Search Success Center
            success_articles = self._search_success_center(search_terms)
            all_kb_articles.extend(success_articles)
            
            # 2. Search Thwack Community
            thwack_articles = self._search_thwack(search_terms)
            all_kb_articles.extend(thwack_articles)
            
            # 3. Search general web with Google
            web_articles = self._search_web(search_terms)
            all_kb_articles.extend(web_articles)
        
        except Exception as e:
            logging.error(f"KB search error: {e}")
        
        # Remove duplicates based on URL
        seen_urls = set()
        unique_articles = []
        for article in all_kb_articles:
            if article['url'] not in seen_urls:
                seen_urls.add(article['url'])
                unique_articles.append(article)
        
        return unique_articles[:10]  # Return top 10 unique results
    
    def _search_success_center(self, search_terms: str) -> List[Dict]:
        """Search SolarWinds Success Center"""
        articles = []
        try:
            # Success Center search URL
            search_url = f"{self.success_center_url}/s/global-search/{search_terms}"
            logging.info(f"Searching Success Center: {search_url}")
            
            response = self.session.get(search_url, timeout=10, allow_redirects=True)
            if response.status_code == 200:
                # Pattern for Success Center articles
                patterns = [
                    r'href="(/SuccessCenter/s/article/[^"]+)"[^>]*>([^<]+)</a>',
                    r'<a[^>]*href="([^"]*SuccessCenter/s/article/[^"]+)"[^>]*>([^<]+)</a>',
                ]
                
                for pattern in patterns:
                    matches = re.findall(pattern, response.text, re.IGNORECASE)
                    for url_path, title in matches:
                        if not url_path.startswith('http'):
                            full_url = f"{self.success_center_url}{url_path}" if url_path.startswith('/') else f"{self.success_center_url}/{url_path}"
                        else:
                            full_url = url_path
                        
                        articles.append({
                            'title': self._clean_title(title),
                            'url': full_url,
                            'source': 'Success Center'
                        })
                        logging.info(f"Found Success Center: {title[:50]}")
        
        except Exception as e:
            logging.warning(f"Success Center search failed: {e}")
        
        return articles[:5]
    
    def _search_thwack(self, search_terms: str) -> List[Dict]:
        """Search Thwack Community"""
        articles = []
        try:
            # Thwack search URL
            search_url = f"{self.thwack_url}/search?q={search_terms}"
            logging.info(f"Searching Thwack: {search_url}")
            
            response = self.session.get(search_url, timeout=10, allow_redirects=True)
            if response.status_code == 200:
                # Pattern for Thwack forum posts and articles
                patterns = [
                    r'href="(/t/[^"]+)"[^>]*>([^<]+)</a>',
                    r'<a[^>]*href="([^"]*thwack\.solarwinds\.com/[^"]+)"[^>]*>([^<]+)</a>',
                ]
                
                for pattern in patterns:
                    matches = re.findall(pattern, response.text, re.IGNORECASE)
                    for url_path, title in matches:
                        if not url_path.startswith('http'):
                            full_url = f"{self.thwack_url}{url_path}" if url_path.startswith('/') else f"{self.thwack_url}/{url_path}"
                        else:
                            full_url = url_path
                        
                        # Skip navigation links
                        if any(skip in full_url.lower() for skip in ['login', 'register', 'profile', 'search']):
                            continue
                        
                        articles.append({
                            'title': self._clean_title(title),
                            'url': full_url,
                            'source': 'Thwack Community'
                        })
                        logging.info(f"Found Thwack: {title[:50]}")
        
        except Exception as e:
            logging.warning(f"Thwack search failed: {e}")
        
        return articles[:5]
    
    def _search_web(self, search_terms: str) -> List[Dict]:
        """Search general web for SolarWinds related articles"""
        articles = []
        try:
            # Google search with site restriction
            search_query = f"{search_terms} solarwinds"
            search_url = f"https://www.google.com/search?q={requests.utils.quote(search_query)}"
            
            logging.info(f"Searching web: {search_query}")
            
            response = self.session.get(search_url, timeout=10)
            if response.status_code == 200:
                # Pattern for Google search results
                patterns = [
                    r'<a[^>]*href="(https?://[^"]*(?:solarwinds\.com|thwack|support)[^"]*)"[^>]*>.*?<h3[^>]*>([^<]+)</h3>',
                    r'href="(/url\?q=(https?://[^&]*(?:solarwinds|thwack)[^&]*)&[^"]*)"[^>]*>.*?<h3[^>]*>([^<]+)</h3>',
                ]
                
                for pattern in patterns:
                    matches = re.findall(pattern, response.text, re.IGNORECASE | re.DOTALL)
                    for match in matches:
                        if len(match) == 2:
                            url, title = match
                        elif len(match) == 3:
                            _, url, title = match
                        else:
                            continue
                        
                        # Decode URL
                        url = requests.utils.unquote(url)
                        
                        articles.append({
                            'title': self._clean_title(title),
                            'url': url,
                            'source': 'Web Search'
                        })
                        logging.info(f"Found Web: {title[:50]}")
        
        except Exception as e:
            logging.warning(f"Web search failed: {e}")
        
        return articles[:3]
    
    def _clean_title(self, title: str) -> str:
        """Clean up article title"""
        # Remove HTML entities
        title = re.sub(r'&[a-z]+;', ' ', title)
        # Remove extra whitespace
        title = ' '.join(title.split())
        return title.strip()[:150]  # Limit length
    
    def _extract_search_terms(self, message: str, category: str) -> str:
        """Extract meaningful search terms from error message"""
        # Remove timestamps and dates
        message = re.sub(r'\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}[,.]?\d*', '', message)
        message = re.sub(r'\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}', '', message)
        
        # Remove year numbers (2024, 2025, etc.)
        message = re.sub(r'\b20\d{2}\b', '', message)
        
        # Remove common log prefixes
        message = re.sub(r'^.*?(INFO|ERROR|WARNING|CRITICAL|DEBUG)\s*[-:]\s*', '', message, flags=re.IGNORECASE)
        
        # Look for quoted error messages (most specific)
        quoted = re.findall(r'"([^"]{10,})"', message)
        if quoted:
            return quoted[0].strip()
        
        # Look for specific error messages after common indicators
        error_indicators = [
            r'(?:Exception|Error):\s*(.{10,100})',
            r'(?:Failed to|Unable to|Cannot|Could not)\s+(.{10,100})',
            r'Message:\s*(.{10,100})',
        ]
        
        for pattern in error_indicators:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                error_text = match.group(1).strip()
                # Clean up the error text
                error_text = re.sub(r'\s+at\s+.*
    
    RESOLUTION_DATABASE = {
        'sql_error': {
            'Deadlock': {
                'description': 'SQL deadlock detected',
                'solutions': [
                    'Review queries in BusinessLayerHost.log for long-running queries',
                    'Check SQL Server Activity Monitor for blocking sessions',
                    'Run: SELECT * FROM sys.dm_tran_locks to identify locked resources',
                    'Consider enabling Read Committed Snapshot Isolation',
                    'Review database maintenance windows to avoid conflicts',
                    'Restart SolarWinds services during low-activity periods'
                ],
                'kb_articles': ['KB Article: How to Resolve SQL Deadlocks in SolarWinds'],
                'prevention': 'Schedule database maintenance during off-peak hours'
            },
            'Connection Failed': {
                'description': 'Cannot connect to SQL Server',
                'solutions': [
                    'Verify SQL Server service is running',
                    'Check SQL Server Configuration Manager for network protocols',
                    'Test connection: sqlcmd -S <server> -U <user> -P <password>',
                    'Verify firewall allows port 1433',
                    'Check SolarWinds connection string in SolarWinds.Orion.Core.dll.config',
                    'Review SQL Server error logs for authentication issues'
                ],
                'kb_articles': ['Troubleshooting SQL Connectivity'],
                'prevention': 'Monitor SQL Server health and set up alerts'
            },
            'Transaction Log Full': {
                'description': 'SQL transaction log is full',
                'solutions': [
                    'Check database recovery model: SELECT name, recovery_model_desc FROM sys.databases',
                    'Backup transaction log: BACKUP LOG [SolarWindsOrion] TO DISK',
                    'Shrink log file: DBCC SHRINKFILE (SolarWindsOrion_log, 1024)',
                    'Review database maintenance plan',
                    'Consider switching to Simple recovery model if not using log backups',
                    'Run Database Maintenance in Configuration Wizard'
                ],
                'kb_articles': ['Managing SolarWinds Database Size'],
                'prevention': 'Schedule regular transaction log backups'
            }
        },
        'connection_error': {
            'Network Unreachable': {
                'description': 'Unable to reach remote devices',
                'solutions': [
                    'Verify network connectivity with ping and traceroute',
                    'Check firewall rules on both SolarWinds server and target',
                    'Verify VLANs and routing configuration',
                    'Check if polling engine is on correct network segment',
                    'Test SNMP: snmpwalk -v2c -c <community> <host>',
                    'Review routing tables and ACLs'
                ],
                'kb_articles': ['Network Connectivity Troubleshooting Guide'],
                'prevention': 'Implement redundant polling engines'
            },
            'Timeout': {
                'description': 'Connection or operation timeout',
                'solutions': [
                    'Increase timeout values in Orion.Web.config',
                    'Check network latency with ping -t',
                    'Review polling intervals - reduce frequency if needed',
                    'Verify target device is not overloaded',
                    'Check for network packet loss',
                    'Review BusinessLayerHost.log for slow queries'
                ],
                'kb_articles': ['Adjusting Timeout Settings'],
                'prevention': 'Optimize polling intervals based on network capacity'
            }
        },
        'authentication_error': {
            'Access Denied': {
                'description': 'Permission or credential issues',
                'solutions': [
                    'Run OrionPermissionChecker.exe to verify permissions',
                    'Verify credentials in Node Management',
                    'Check Windows Event Viewer for authentication failures',
                    'Ensure service account has required permissions',
                    'For SNMP: verify community strings match',
                    'For WMI: Run wmimgmt.msc and check DCOM permissions',
                    'Reset credentials: Settings > Manage Nodes > Edit Properties'
                ],
                'kb_articles': ['SolarWinds Service Account Requirements', 'SNMP Configuration Guide'],
                'prevention': 'Use group-managed service accounts and document credential rotation'
            },
            'Login Failed': {
                'description': 'Authentication failure',
                'solutions': [
                    'Verify account is not locked: net user <username> /domain',
                    'Check password expiration: net user <username>',
                    'Ensure account has proper SQL permissions',
                    'Verify SolarWinds service account permissions',
                    'Check Active Directory group membership',
                    'Review IIS application pool identity'
                ],
                'kb_articles': ['Configuring Service Accounts'],
                'prevention': 'Set passwords to never expire for service accounts'
            }
        },
        'service_error': {
            'Service Stopped': {
                'description': 'SolarWinds service not running',
                'solutions': [
                    'Check Windows Event Viewer for crash details',
                    'Review service dependencies: sc qc <servicename>',
                    'Restart service: net start "SolarWinds <ServiceName>"',
                    'Check BusinessLayerHost.log for errors before crash',
                    'Verify SQL Server connectivity',
                    'Increase service timeout: sc config <service> start=delayed-auto',
                    'Check for .NET Framework issues'
                ],
                'kb_articles': ['Troubleshooting Service Failures'],
                'prevention': 'Monitor services with SolarWinds SAM'
            }
        },
        'polling_error': {
            'SNMP Timeout': {
                'description': 'SNMP polling failures',
                'solutions': [
                    'Verify SNMP service is running on target device',
                    'Test SNMP manually: snmpget -v2c -c <community> <host> sysDescr.0',
                    'Check SNMP community string is correct',
                    'Verify firewall allows UDP 161',
                    'Increase SNMP timeout in Polling Settings',
                    'Check device CPU usage - SNMP may be slow',
                    'Review MIB compatibility'
                ],
                'kb_articles': ['SNMP Polling Best Practices'],
                'prevention': 'Use SNMPv3 for better reliability and security'
            },
            'WMI Error': {
                'description': 'WMI polling failures for Windows devices',
                'solutions': [
                    'Verify WMI service: Get-Service Winmgmt',
                    'Test WMI: wmic /node:<host> /user:<user> computersystem get name',
                    'Rebuild WMI repository: winmgmt /resetrepository',
                    'Check DCOM permissions: dcomcnfg',
                    'Verify firewall allows port 135 and dynamic RPC ports',
                    'Run OrionPermissionChecker for WMI validation',
                    'Review security log for audit failures'
                ],
                'kb_articles': ['WMI Troubleshooting Guide', 'Windows Firewall Configuration'],
                'prevention': 'Regular WMI health checks and monitoring'
            }
        },
        'memory_error': {
            'Out of Memory': {
                'description': 'Application or system memory exhaustion',
                'solutions': [
                    'Check available RAM: Get-Counter "\\Memory\\Available MBytes"',
                    'Restart SolarWinds services to free memory',
                    'Review BusinessLayerHost.log for memory leaks',
                    'Check Task Manager for memory-consuming processes',
                    'Increase server RAM (minimum 16GB recommended)',
                    'Reduce polling frequency for non-critical nodes',
                    'Clear IIS application pool recycling',
                    'Review custom SQL queries and reports'
                ],
                'kb_articles': ['SolarWinds Performance Tuning', 'Memory Requirements'],
                'prevention': 'Monitor memory usage and plan capacity upgrades'
            }
        },
        'web_error': {
            'HTTP 500': {
                'description': 'Internal server error',
                'solutions': [
                    'Check OrionWeb.log for detailed error messages',
                    'Review IIS logs: C:\\inetpub\\logs\\LogFiles',
                    'Verify application pool is running',
                    'Check .NET Framework version compatibility',
                    'Clear browser cache and cookies',
                    'Recycle IIS application pool: iisreset',
                    'Verify database connectivity from web server',
                    'Check SWIS service status'
                ],
                'kb_articles': ['Web Console Troubleshooting'],
                'prevention': 'Regular IIS health monitoring'
            }
        },
        'license_error': {
            'License Expired': {
                'description': 'SolarWinds license issue',
                'solutions': [
                    'Check license status: Settings > License Manager',
                    'Contact SolarWinds support for license renewal',
                    'Import new license file if available',
                    'Verify license count matches deployed elements',
                    'Check for evaluation/trial expiration',
                    'Review maintenance contract status'
                ],
                'kb_articles': ['License Management Guide'],
                'prevention': 'Set calendar reminders 30 days before expiration'
            }
        },
        'job_error': {
            'Job Failed': {
                'description': 'Scheduled job or task failure',
                'solutions': [
                    'Review JobEngine logs for specific error details',
                    'Check job schedule and dependencies',
                    'Verify job account permissions',
                    'Test job manually: Settings > Manage Jobs',
                    'Check database connectivity during job execution',
                    'Review job query syntax for errors',
                    'Verify adequate system resources during job runtime'
                ],
                'kb_articles': ['Job Engine Troubleshooting'],
                'prevention': 'Schedule intensive jobs during maintenance windows'
            }
        },
        'ha_error': {
            'Failover Failed': {
                'description': 'High Availability failover issues',
                'solutions': [
                    'Check HA logs for specific failure reason',
                    'Verify network connectivity between HA nodes',
                    'Test database replication status',
                    'Check Windows Failover Cluster status',
                    'Verify shared storage accessibility',
                    'Review HA configuration: Settings > High Availability',
                    'Ensure both nodes meet system requirements',
                    'Check for Windows updates or patches on nodes'
                ],
                'kb_articles': ['High Availability Configuration Guide', 'HA Troubleshooting'],
                'prevention': 'Regular HA testing and monitoring'
            }
        },
        'certificate_error': {
            'Certificate Expired': {
                'description': 'SSL/TLS certificate issues',
                'solutions': [
                    'Check certificate expiration: Get-ChildItem Cert:\\LocalMachine\\My',
                    'Renew certificate through Certificate Manager (certmgr.msc)',
                    'Update certificate binding in IIS',
                    'Verify certificate chain is complete',
                    'Check certificate permissions for service account',
                    'Update certificate in SolarWinds: Settings > Certificates',
                    'Clear SSL cache: certutil -urlcache * delete'
                ],
                'kb_articles': ['SSL Certificate Management'],
                'prevention': 'Monitor certificate expiration dates'
            }
        },
        'configuration_error': {
            'Configuration Invalid': {
                'description': 'Configuration file or setting issues',
                'solutions': [
                    'Review ConfigurationWizard.log for specific errors',
                    'Validate XML configuration files',
                    'Compare with backup configuration files',
                    'Re-run Configuration Wizard',
                    'Check file permissions on configuration directories',
                    'Verify database schema version matches application version',
                    'Review recent configuration changes'
                ],
                'kb_articles': ['Configuration Best Practices'],
                'prevention': 'Backup configurations before changes'
            }
        }
    }
    
    def find_resolution(self, issue: Dict) -> Dict:
        """Find resolution for a specific issue"""
        category = issue['category']
        message = issue['sample_message']
        
        resolutions = []
        kb_articles = []
        
        # Search SolarWinds KB, Success Center, Thwack and web for real articles
        logging.info(f"Searching for solutions: {category}")
        kb_articles = self.search_solarwinds_kb(message, category)
        
        if category in self.RESOLUTION_DATABASE:
            # Try to match specific error type
            for error_type, resolution_data in self.RESOLUTION_DATABASE[category].items():
                if any(keyword.lower() in message.lower() for keyword in error_type.split()):
                    # Merge KB articles with resolution data
                    resolution_copy = resolution_data.copy()
                    if kb_articles:
                        resolution_copy['kb_articles'] = kb_articles
                    resolutions.append(resolution_copy)
            
            # If no specific match, provide generic resolution for category
            if not resolutions:
                first_resolution = list(self.RESOLUTION_DATABASE[category].values())[0].copy()
                if kb_articles:
                    first_resolution['kb_articles'] = kb_articles
                resolutions.append(first_resolution)
        else:
            # Generic troubleshooting steps
            resolutions.append({
                'description': 'General troubleshooting required',
                'solutions': [
                    'Review the specific log file for detailed error messages',
                    'Check Windows Event Viewer for system-level errors',
                    'Verify all SolarWinds services are running',
                    'Test database connectivity',
                    'Review recent changes to the environment',
                    'Check SolarWinds Support portal for similar issues',
                    'Contact SolarWinds Technical Support if issue persists'
                ],
                'kb_articles': kb_articles if kb_articles else [],
                'prevention': 'Regular system health checks'
            })
        
        return {
            'issue': issue,
            'resolutions': resolutions,
            'priority': self._calculate_priority(issue)
        }
    
    def _calculate_priority(self, issue: Dict) -> int:
        """Calculate issue priority (1=highest, 5=lowest)"""
        severity_priority = {
            'CRITICAL': 1,
            'ERROR': 2,
            'WARNING': 3,
            'INFO': 4
        }
        
        base_priority = severity_priority.get(issue['severity'], 4)
        
        # Adjust based on frequency
        if issue['count'] > 100:
            base_priority = max(1, base_priority - 1)
        elif issue['count'] > 10:
            base_priority = max(1, base_priority - 0.5)
        
        return int(base_priority)


class ReportGenerator:
    """Generates comprehensive HTML reports"""
    
    def generate_html_report(self, results: List[Dict], log_stats: Dict) -> str:
        """Generate detailed HTML report"""
        
        html = """
<!DOCTYPE html>
<html>
<head>
    <title>SolarWinds Log Analysis Report</title>
    <meta charset="UTF-8">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .header .subtitle {
            font-size: 1.1em;
            opacity: 0.9;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px 40px;
            background: #f8f9fa;
            border-bottom: 1px solid #dee2e6;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #2a5298;
        }
        .stat-label {
            color: #6c757d;
            margin-top: 5px;
            font-size: 0.9em;
        }
        .content {
            padding: 40px;
        }
        .issue-card {
            background: white;
            border: 1px solid #dee2e6;
            border-left: 5px solid #dc3545;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }
        .issue-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        .issue-card.priority-1 { border-left-color: #dc3545; }
        .issue-card.priority-2 { border-left-color: #fd7e14; }
        .issue-card.priority-3 { border-left-color: #ffc107; }
        .issue-card.priority-4 { border-left-color: #28a745; }
        .issue-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
        }
        .issue-title {
            font-size: 1.4em;
            color: #212529;
            font-weight: 600;
        }
        .badges {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        .badge {
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            display: inline-block;
        }
        .badge.critical { background: #dc3545; color: white; }
        .badge.error { background: #fd7e14; color: white; }
        .badge.warning { background: #ffc107; color: #212529; }
        .badge.info { background: #17a2b8; color: white; }
        .badge.count { background: #6c757d; color: white; }
        .badge.category { background: #007bff; color: white; }
        .issue-details {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
        }
        .meta-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 15px 0;
            font-size: 0.9em;
        }
        .meta-item {
            display: flex;
            flex-direction: column;
        }
        .meta-label {
            color: #6c757d;
            font-size: 0.85em;
            margin-bottom: 3px;
        }
        .meta-value {
            color: #212529;
            font-weight: 500;
        }
        .resolution-section {
            margin-top: 20px;
            padding-top: 20px;
            border-top: 2px solid #e9ecef;
        }
        .resolution-title {
            font-size: 1.2em;
            color: #28a745;
            margin-bottom: 15px;
            font-weight: 600;
        }
        .resolution-box {
            background: #f0fff4;
            border: 1px solid #c3e6cb;
            border-radius: 5px;
            padding: 20px;
            margin-bottom: 15px;
        }
        .resolution-description {
            font-weight: 600;
            color: #155724;
            margin-bottom: 10px;
        }
        .solution-steps {
            margin: 10px 0;
        }
        .solution-steps li {
            margin: 8px 0;
            padding-left: 10px;
            line-height: 1.6;
        }
        .kb-articles {
            margin-top: 10px;
            padding: 10px;
            background: #e7f3ff;
            border-radius: 4px;
            line-height: 1.8;
        }
        .kb-articles a {
            color: #004085;
            text-decoration: none;
            display: block;
            padding: 3px 0;
        }
        .kb-articles a:hover {
            text-decoration: underline;
            color: #002752;
        }
        .kb-articles strong {
            color: #004085;
        }
        .prevention-tip {
            margin-top: 10px;
            padding: 10px;
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            border-radius: 4px;
            font-style: italic;
        }
        .occurrences {
            margin-top: 15px;
        }
        .occurrence-item {
            padding: 8px;
            background: #f8f9fa;
            border-left: 3px solid #6c757d;
            margin: 5px 0;
            font-size: 0.85em;
        }
        .footer {
            background: #f8f9fa;
            padding: 20px 40px;
            text-align: center;
            color: #6c757d;
            border-top: 1px solid #dee2e6;
        }
        .priority-legend {
            display: flex;
            gap: 20px;
            justify-content: center;
            margin-bottom: 30px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
        }
        .legend-item {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .legend-color {
            width: 20px;
            height: 20px;
            border-radius: 3px;
        }
        @media print {
            body { background: white; padding: 0; }
            .issue-card { page-break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 SolarWinds Log Analysis Report</h1>
            <div class="subtitle">Generated: """ + datetime.now().strftime('%B %d, %Y at %I:%M %p') + """</div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">""" + str(len(results)) + """</div>
                <div class="stat-label">Total Issues Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">""" + str(log_stats.get('files_analyzed', 0)) + """</div>
                <div class="stat-label">Log Files Analyzed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">""" + str(log_stats.get('critical_count', 0)) + """</div>
                <div class="stat-label">Critical Issues</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">""" + str(log_stats.get('error_count', 0)) + """</div>
                <div class="stat-label">Errors</div>
            </div>
        </div>
        
        <div class="content">
            <div class="priority-legend">
                <div class="legend-item">
                    <div class="legend-color" style="background: #dc3545;"></div>
                    <span>Priority 1 - Critical</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #fd7e14;"></div>
                    <span>Priority 2 - High</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #ffc107;"></div>
                    <span>Priority 3 - Medium</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #28a745;"></div>
                    <span>Priority 4 - Low</span>
                </div>
            </div>
"""
        
        for idx, result in enumerate(results, 1):
            issue = result['issue']
            priority = result['priority']
            
            html += f"""
            <div class="issue-card priority-{priority}">
                <div class="issue-header">
                    <div class="issue-title">Issue #{idx}: {issue['category'].replace('_', ' ').title()}</div>
                    <div class="badges">
                        <span class="badge {issue['severity'].lower()}">{issue['severity']}</span>
                        <span class="badge count">{issue['count']} occurrences</span>
                        <span class="badge category">{issue['category']}</span>
                    </div>
                </div>
                
                <div class="issue-details">
                    {issue['sample_message'][:500]}{'...' if len(issue['sample_message']) > 500 else ''}
                </div>
                
                <div class="meta-info">
                    <div class="meta-item">
                        <span class="meta-label">First Occurrence</span>
                        <span class="meta-value">{issue['first_occurrence']}</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Last Occurrence</span>
                        <span class="meta-value">{issue['last_occurrence']}</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Affected Files</span>
                        <span class="meta-value">{', '.join(issue['affected_files'][:3])}</span>
                    </div>
                    {'<div class="meta-item"><span class="meta-label">Exception Type</span><span class="meta-value">' + issue['exception_type'] + '</span></div>' if issue.get('exception_type') else ''}
                </div>
                
                <div class="resolution-section">
                    <div class="resolution-title">📋 Recommended Solutions</div>
"""
            
            for resolution in result['resolutions']:
                html += f"""
                    <div class="resolution-box">
                        <div class="resolution-description">{resolution['description']}</div>
                        <ol class="solution-steps">
"""
                for step in resolution['solutions']:
                    html += f"                            <li>{step}</li>\n"
                
                html += """                        </ol>
"""
                
                if resolution.get('kb_articles'):
                    html += """                        <div class="kb-articles">
                            <strong>📚 Related Knowledge Base Articles & Community Posts:</strong><br><br>
"""
                    for kb in resolution['kb_articles']:
                        if isinstance(kb, dict):
                            source_icon = '🔗'
                            if 'Success Center' in kb.get('source', ''):
                                source_icon = '📘'
                            elif 'Thwack' in kb.get('source', ''):
                                source_icon = '💬'
                            elif 'Web' in kb.get('source', ''):
                                source_icon = '🌐'
                            
                            html += f"""                            <div style="margin-bottom: 8px;">
                                {source_icon} <a href="{kb['url']}" target="_blank" style="color: #004085; text-decoration: none; font-weight: 500;">{kb['title']}</a>
                                <span style="color: #6c757d; font-size: 0.85em; margin-left: 8px;">({kb.get('source', 'Source')})</span>
                            </div>
"""
                        else:
                            html += f"""                            <div style="margin-bottom: 8px;">📄 {kb}</div>
"""
                    html += """                        </div>
"""
                
                if resolution.get('prevention'):
                    html += f"""                        <div class="prevention-tip">
                            <strong>💡 Prevention:</strong> {resolution['prevention']}
                        </div>
"""
                
                html += """                    </div>
"""
            
            # Add sample occurrences
            if issue.get('all_occurrences'):
                html += """                    <div class="occurrences">
                        <strong>Recent Occurrences:</strong>
"""
                for occ in issue['all_occurrences'][:5]:
                    html += f"""                        <div class="occurrence-item">
                            <strong>{occ['timestamp']}</strong> - {occ['file']} (Line {occ['line_number']})
                        </div>
"""
                html += """                    </div>
"""
            
            html += """                </div>
            </div>
"""
        
        html += """
        </div>
        
        <div class="footer">
            <p>SolarWinds Log Analyzer - Automated Issue Detection & Resolution</p>
            <p>For additional support, visit SolarWinds Support Portal or contact Technical Support</p>
        </div>
    </div>
</body>
</html>
"""
        return html


class SolarWindsLogAnalyzer:
    """Main application class"""
    
    def __init__(self, hours_back: int = 24):
        self.hours_back = hours_back
        self.path_manager = LogPathManager()
        self.parser = LogParser()
        self.aggregator = IssueAggregator()
        self.resolver = ResolutionFinder()
        self.report_generator = ReportGenerator()
    
    def analyze(self) -> Tuple[List[Dict], Dict]:
        """Run complete analysis"""
        logging.info("=" * 70)
        logging.info("Starting SolarWinds Log Analysis")
        logging.info("=" * 70)
        
        # Get log files
        logging.info(f"\n📁 Scanning for log files modified in last {self.hours_back} hours...")
        log_files = self.path_manager.get_all_log_files(self.hours_back)
        
        if not log_files:
            logging.warning("No log files found! Check if paths are correct.")
            return [], {'files_analyzed': 0}
        
        # Parse all log files
        all_issues = []
        files_analyzed = 0
        
        for category, files in log_files.items():
            logging.info(f"\n🔍 Analyzing {category} logs...")
            for file_path in files:
                logging.info(f"   Processing: {os.path.basename(file_path)}")
                issues = self.parser.parse_log_file(file_path)
                all_issues.extend(issues)
                files_analyzed += 1
        
        logging.info(f"\n✅ Found {len(all_issues)} total issue entries")
        
        # Aggregate similar issues
        logging.info("\n📊 Aggregating and categorizing issues...")
        aggregated_issues = self.aggregator.aggregate_issues(all_issues)
        logging.info(f"✅ Identified {len(aggregated_issues)} unique issue patterns")
        
        # Find resolutions
        logging.info("\n🔧 Finding resolutions for issues...")
        results = []
        for issue in aggregated_issues:
            resolution = self.resolver.find_resolution(issue)
            results.append(resolution)
        
        # Calculate statistics
        stats = {
            'files_analyzed': files_analyzed,
            'total_issues': len(all_issues),
            'unique_patterns': len(aggregated_issues),
            'critical_count': sum(1 for i in aggregated_issues if i['severity'] == 'CRITICAL'),
            'error_count': sum(1 for i in aggregated_issues if i['severity'] == 'ERROR'),
            'warning_count': sum(1 for i in aggregated_issues if i['severity'] == 'WARNING')
        }
        
        logging.info("\n" + "=" * 70)
        logging.info("Analysis Statistics:")
        logging.info(f"  Files Analyzed: {stats['files_analyzed']}")
        logging.info(f"  Total Issues: {stats['total_issues']}")
        logging.info(f"  Unique Patterns: {stats['unique_patterns']}")
        logging.info(f"  Critical: {stats['critical_count']}")
        logging.info(f"  Errors: {stats['error_count']}")
        logging.info(f"  Warnings: {stats['warning_count']}")
        logging.info("=" * 70)
        
        return results, stats
    
    def generate_report(self, results: List[Dict], stats: Dict, output_file: str = None):
        """Generate HTML report"""
        if not output_file:
            output_file = f"SolarWinds_Analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        logging.info(f"\n📝 Generating report: {output_file}")
        html_content = self.report_generator.generate_html_report(results, stats)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logging.info(f"✅ Report saved successfully!")
        return output_file
    
    def print_summary(self, results: List[Dict]):
        """Print console summary of top issues"""
        print("\n" + "=" * 70)
        print("🔥 TOP 10 ISSUES REQUIRING ATTENTION")
        print("=" * 70)
        
        for idx, result in enumerate(results[:10], 1):
            issue = result['issue']
            print(f"\n{idx}. [{issue['severity']}] {issue['category'].replace('_', ' ').title()}")
            print(f"   Count: {issue['count']} occurrences")
            print(f"   Priority: {result['priority']}")
            print(f"   Files: {', '.join(issue['affected_files'][:2])}")
            print(f"   Message: {issue['sample_message'][:100]}...")


def main():
    """Main entry point"""
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║        SolarWinds Log Analyzer & Resolution Finder v2.0              ║
║                                                                      ║
║  Automatically analyzes SolarWinds logs, identifies issues,          ║
║  and provides step-by-step resolutions                               ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
    """)
    
    # Get time range
    while True:
        try:
            hours = input("\nAnalyze logs from last X hours [default: 24]: ").strip()
            hours = int(hours) if hours else 24
            break
        except ValueError:
            print("Please enter a valid number")
    
    # Create analyzer
    analyzer = SolarWindsLogAnalyzer(hours_back=hours)
    
    try:
        # Run analysis
        results, stats = analyzer.analyze()
        
        if not results:
            print("\n✅ No issues found in the specified time period!")
            return
        
        # Print summary to console
        analyzer.print_summary(results)
        
        # Generate report
        report_file = analyzer.generate_report(results, stats)
        
        print(f"\n{'=' * 70}")
        print(f"✅ Analysis Complete!")
        print(f"📄 Full report saved to: {report_file}")
        print(f"💡 Open the HTML file in your browser for detailed resolutions")
        print(f"{'=' * 70}")
        
        # Ask if user wants to open report
        open_report = input("\nOpen report in browser? (y/n): ").strip().lower()
        if open_report == 'y':
            import webbrowser
            webbrowser.open(report_file)
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Analysis cancelled by user")
    except Exception as e:
        logging.error(f"Error during analysis: {e}", exc_info=True)
        print(f"\n❌ Error: {e}")
        print("Check solarwinds_log_analyzer.log for details")


if __name__ == "__main__":
    main(), '', error_text)  # Remove stack trace
                error_text = re.sub(r'\s+in\s+.*
    
    RESOLUTION_DATABASE = {
        'sql_error': {
            'Deadlock': {
                'description': 'SQL deadlock detected',
                'solutions': [
                    'Review queries in BusinessLayerHost.log for long-running queries',
                    'Check SQL Server Activity Monitor for blocking sessions',
                    'Run: SELECT * FROM sys.dm_tran_locks to identify locked resources',
                    'Consider enabling Read Committed Snapshot Isolation',
                    'Review database maintenance windows to avoid conflicts',
                    'Restart SolarWinds services during low-activity periods'
                ],
                'kb_articles': ['KB Article: How to Resolve SQL Deadlocks in SolarWinds'],
                'prevention': 'Schedule database maintenance during off-peak hours'
            },
            'Connection Failed': {
                'description': 'Cannot connect to SQL Server',
                'solutions': [
                    'Verify SQL Server service is running',
                    'Check SQL Server Configuration Manager for network protocols',
                    'Test connection: sqlcmd -S <server> -U <user> -P <password>',
                    'Verify firewall allows port 1433',
                    'Check SolarWinds connection string in SolarWinds.Orion.Core.dll.config',
                    'Review SQL Server error logs for authentication issues'
                ],
                'kb_articles': ['Troubleshooting SQL Connectivity'],
                'prevention': 'Monitor SQL Server health and set up alerts'
            },
            'Transaction Log Full': {
                'description': 'SQL transaction log is full',
                'solutions': [
                    'Check database recovery model: SELECT name, recovery_model_desc FROM sys.databases',
                    'Backup transaction log: BACKUP LOG [SolarWindsOrion] TO DISK',
                    'Shrink log file: DBCC SHRINKFILE (SolarWindsOrion_log, 1024)',
                    'Review database maintenance plan',
                    'Consider switching to Simple recovery model if not using log backups',
                    'Run Database Maintenance in Configuration Wizard'
                ],
                'kb_articles': ['Managing SolarWinds Database Size'],
                'prevention': 'Schedule regular transaction log backups'
            }
        },
        'connection_error': {
            'Network Unreachable': {
                'description': 'Unable to reach remote devices',
                'solutions': [
                    'Verify network connectivity with ping and traceroute',
                    'Check firewall rules on both SolarWinds server and target',
                    'Verify VLANs and routing configuration',
                    'Check if polling engine is on correct network segment',
                    'Test SNMP: snmpwalk -v2c -c <community> <host>',
                    'Review routing tables and ACLs'
                ],
                'kb_articles': ['Network Connectivity Troubleshooting Guide'],
                'prevention': 'Implement redundant polling engines'
            },
            'Timeout': {
                'description': 'Connection or operation timeout',
                'solutions': [
                    'Increase timeout values in Orion.Web.config',
                    'Check network latency with ping -t',
                    'Review polling intervals - reduce frequency if needed',
                    'Verify target device is not overloaded',
                    'Check for network packet loss',
                    'Review BusinessLayerHost.log for slow queries'
                ],
                'kb_articles': ['Adjusting Timeout Settings'],
                'prevention': 'Optimize polling intervals based on network capacity'
            }
        },
        'authentication_error': {
            'Access Denied': {
                'description': 'Permission or credential issues',
                'solutions': [
                    'Run OrionPermissionChecker.exe to verify permissions',
                    'Verify credentials in Node Management',
                    'Check Windows Event Viewer for authentication failures',
                    'Ensure service account has required permissions',
                    'For SNMP: verify community strings match',
                    'For WMI: Run wmimgmt.msc and check DCOM permissions',
                    'Reset credentials: Settings > Manage Nodes > Edit Properties'
                ],
                'kb_articles': ['SolarWinds Service Account Requirements', 'SNMP Configuration Guide'],
                'prevention': 'Use group-managed service accounts and document credential rotation'
            },
            'Login Failed': {
                'description': 'Authentication failure',
                'solutions': [
                    'Verify account is not locked: net user <username> /domain',
                    'Check password expiration: net user <username>',
                    'Ensure account has proper SQL permissions',
                    'Verify SolarWinds service account permissions',
                    'Check Active Directory group membership',
                    'Review IIS application pool identity'
                ],
                'kb_articles': ['Configuring Service Accounts'],
                'prevention': 'Set passwords to never expire for service accounts'
            }
        },
        'service_error': {
            'Service Stopped': {
                'description': 'SolarWinds service not running',
                'solutions': [
                    'Check Windows Event Viewer for crash details',
                    'Review service dependencies: sc qc <servicename>',
                    'Restart service: net start "SolarWinds <ServiceName>"',
                    'Check BusinessLayerHost.log for errors before crash',
                    'Verify SQL Server connectivity',
                    'Increase service timeout: sc config <service> start=delayed-auto',
                    'Check for .NET Framework issues'
                ],
                'kb_articles': ['Troubleshooting Service Failures'],
                'prevention': 'Monitor services with SolarWinds SAM'
            }
        },
        'polling_error': {
            'SNMP Timeout': {
                'description': 'SNMP polling failures',
                'solutions': [
                    'Verify SNMP service is running on target device',
                    'Test SNMP manually: snmpget -v2c -c <community> <host> sysDescr.0',
                    'Check SNMP community string is correct',
                    'Verify firewall allows UDP 161',
                    'Increase SNMP timeout in Polling Settings',
                    'Check device CPU usage - SNMP may be slow',
                    'Review MIB compatibility'
                ],
                'kb_articles': ['SNMP Polling Best Practices'],
                'prevention': 'Use SNMPv3 for better reliability and security'
            },
            'WMI Error': {
                'description': 'WMI polling failures for Windows devices',
                'solutions': [
                    'Verify WMI service: Get-Service Winmgmt',
                    'Test WMI: wmic /node:<host> /user:<user> computersystem get name',
                    'Rebuild WMI repository: winmgmt /resetrepository',
                    'Check DCOM permissions: dcomcnfg',
                    'Verify firewall allows port 135 and dynamic RPC ports',
                    'Run OrionPermissionChecker for WMI validation',
                    'Review security log for audit failures'
                ],
                'kb_articles': ['WMI Troubleshooting Guide', 'Windows Firewall Configuration'],
                'prevention': 'Regular WMI health checks and monitoring'
            }
        },
        'memory_error': {
            'Out of Memory': {
                'description': 'Application or system memory exhaustion',
                'solutions': [
                    'Check available RAM: Get-Counter "\\Memory\\Available MBytes"',
                    'Restart SolarWinds services to free memory',
                    'Review BusinessLayerHost.log for memory leaks',
                    'Check Task Manager for memory-consuming processes',
                    'Increase server RAM (minimum 16GB recommended)',
                    'Reduce polling frequency for non-critical nodes',
                    'Clear IIS application pool recycling',
                    'Review custom SQL queries and reports'
                ],
                'kb_articles': ['SolarWinds Performance Tuning', 'Memory Requirements'],
                'prevention': 'Monitor memory usage and plan capacity upgrades'
            }
        },
        'web_error': {
            'HTTP 500': {
                'description': 'Internal server error',
                'solutions': [
                    'Check OrionWeb.log for detailed error messages',
                    'Review IIS logs: C:\\inetpub\\logs\\LogFiles',
                    'Verify application pool is running',
                    'Check .NET Framework version compatibility',
                    'Clear browser cache and cookies',
                    'Recycle IIS application pool: iisreset',
                    'Verify database connectivity from web server',
                    'Check SWIS service status'
                ],
                'kb_articles': ['Web Console Troubleshooting'],
                'prevention': 'Regular IIS health monitoring'
            }
        },
        'license_error': {
            'License Expired': {
                'description': 'SolarWinds license issue',
                'solutions': [
                    'Check license status: Settings > License Manager',
                    'Contact SolarWinds support for license renewal',
                    'Import new license file if available',
                    'Verify license count matches deployed elements',
                    'Check for evaluation/trial expiration',
                    'Review maintenance contract status'
                ],
                'kb_articles': ['License Management Guide'],
                'prevention': 'Set calendar reminders 30 days before expiration'
            }
        },
        'job_error': {
            'Job Failed': {
                'description': 'Scheduled job or task failure',
                'solutions': [
                    'Review JobEngine logs for specific error details',
                    'Check job schedule and dependencies',
                    'Verify job account permissions',
                    'Test job manually: Settings > Manage Jobs',
                    'Check database connectivity during job execution',
                    'Review job query syntax for errors',
                    'Verify adequate system resources during job runtime'
                ],
                'kb_articles': ['Job Engine Troubleshooting'],
                'prevention': 'Schedule intensive jobs during maintenance windows'
            }
        },
        'ha_error': {
            'Failover Failed': {
                'description': 'High Availability failover issues',
                'solutions': [
                    'Check HA logs for specific failure reason',
                    'Verify network connectivity between HA nodes',
                    'Test database replication status',
                    'Check Windows Failover Cluster status',
                    'Verify shared storage accessibility',
                    'Review HA configuration: Settings > High Availability',
                    'Ensure both nodes meet system requirements',
                    'Check for Windows updates or patches on nodes'
                ],
                'kb_articles': ['High Availability Configuration Guide', 'HA Troubleshooting'],
                'prevention': 'Regular HA testing and monitoring'
            }
        },
        'certificate_error': {
            'Certificate Expired': {
                'description': 'SSL/TLS certificate issues',
                'solutions': [
                    'Check certificate expiration: Get-ChildItem Cert:\\LocalMachine\\My',
                    'Renew certificate through Certificate Manager (certmgr.msc)',
                    'Update certificate binding in IIS',
                    'Verify certificate chain is complete',
                    'Check certificate permissions for service account',
                    'Update certificate in SolarWinds: Settings > Certificates',
                    'Clear SSL cache: certutil -urlcache * delete'
                ],
                'kb_articles': ['SSL Certificate Management'],
                'prevention': 'Monitor certificate expiration dates'
            }
        },
        'configuration_error': {
            'Configuration Invalid': {
                'description': 'Configuration file or setting issues',
                'solutions': [
                    'Review ConfigurationWizard.log for specific errors',
                    'Validate XML configuration files',
                    'Compare with backup configuration files',
                    'Re-run Configuration Wizard',
                    'Check file permissions on configuration directories',
                    'Verify database schema version matches application version',
                    'Review recent configuration changes'
                ],
                'kb_articles': ['Configuration Best Practices'],
                'prevention': 'Backup configurations before changes'
            }
        }
    }
    
    def find_resolution(self, issue: Dict) -> Dict:
        """Find resolution for a specific issue"""
        category = issue['category']
        message = issue['sample_message']
        
        resolutions = []
        kb_articles = []
        
        # Search SolarWinds KB for real articles
        logging.info(f"Searching KB for: {category}")
        kb_articles = self.search_solarwinds_kb(message)
        
        if category in self.RESOLUTION_DATABASE:
            # Try to match specific error type
            for error_type, resolution_data in self.RESOLUTION_DATABASE[category].items():
                if any(keyword.lower() in message.lower() for keyword in error_type.split()):
                    # Merge KB articles with resolution data
                    resolution_copy = resolution_data.copy()
                    if kb_articles:
                        resolution_copy['kb_articles'] = kb_articles
                    resolutions.append(resolution_copy)
            
            # If no specific match, provide generic resolution for category
            if not resolutions:
                first_resolution = list(self.RESOLUTION_DATABASE[category].values())[0].copy()
                if kb_articles:
                    first_resolution['kb_articles'] = kb_articles
                resolutions.append(first_resolution)
        else:
            # Generic troubleshooting steps
            resolutions.append({
                'description': 'General troubleshooting required',
                'solutions': [
                    'Review the specific log file for detailed error messages',
                    'Check Windows Event Viewer for system-level errors',
                    'Verify all SolarWinds services are running',
                    'Test database connectivity',
                    'Review recent changes to the environment',
                    'Check SolarWinds Support portal for similar issues',
                    'Contact SolarWinds Technical Support if issue persists'
                ],
                'kb_articles': kb_articles if kb_articles else [],
                'prevention': 'Regular system health checks'
            })
        
        return {
            'issue': issue,
            'resolutions': resolutions,
            'priority': self._calculate_priority(issue)
        }
    
    def _calculate_priority(self, issue: Dict) -> int:
        """Calculate issue priority (1=highest, 5=lowest)"""
        severity_priority = {
            'CRITICAL': 1,
            'ERROR': 2,
            'WARNING': 3,
            'INFO': 4
        }
        
        base_priority = severity_priority.get(issue['severity'], 4)
        
        # Adjust based on frequency
        if issue['count'] > 100:
            base_priority = max(1, base_priority - 1)
        elif issue['count'] > 10:
            base_priority = max(1, base_priority - 0.5)
        
        return int(base_priority)


class ReportGenerator:
    """Generates comprehensive HTML reports"""
    
    def generate_html_report(self, results: List[Dict], log_stats: Dict) -> str:
        """Generate detailed HTML report"""
        
        html = """
<!DOCTYPE html>
<html>
<head>
    <title>SolarWinds Log Analysis Report</title>
    <meta charset="UTF-8">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .header .subtitle {
            font-size: 1.1em;
            opacity: 0.9;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px 40px;
            background: #f8f9fa;
            border-bottom: 1px solid #dee2e6;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #2a5298;
        }
        .stat-label {
            color: #6c757d;
            margin-top: 5px;
            font-size: 0.9em;
        }
        .content {
            padding: 40px;
        }
        .issue-card {
            background: white;
            border: 1px solid #dee2e6;
            border-left: 5px solid #dc3545;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }
        .issue-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        .issue-card.priority-1 { border-left-color: #dc3545; }
        .issue-card.priority-2 { border-left-color: #fd7e14; }
        .issue-card.priority-3 { border-left-color: #ffc107; }
        .issue-card.priority-4 { border-left-color: #28a745; }
        .issue-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
        }
        .issue-title {
            font-size: 1.4em;
            color: #212529;
            font-weight: 600;
        }
        .badges {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        .badge {
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            display: inline-block;
        }
        .badge.critical { background: #dc3545; color: white; }
        .badge.error { background: #fd7e14; color: white; }
        .badge.warning { background: #ffc107; color: #212529; }
        .badge.info { background: #17a2b8; color: white; }
        .badge.count { background: #6c757d; color: white; }
        .badge.category { background: #007bff; color: white; }
        .issue-details {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
        }
        .meta-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 15px 0;
            font-size: 0.9em;
        }
        .meta-item {
            display: flex;
            flex-direction: column;
        }
        .meta-label {
            color: #6c757d;
            font-size: 0.85em;
            margin-bottom: 3px;
        }
        .meta-value {
            color: #212529;
            font-weight: 500;
        }
        .resolution-section {
            margin-top: 20px;
            padding-top: 20px;
            border-top: 2px solid #e9ecef;
        }
        .resolution-title {
            font-size: 1.2em;
            color: #28a745;
            margin-bottom: 15px;
            font-weight: 600;
        }
        .resolution-box {
            background: #f0fff4;
            border: 1px solid #c3e6cb;
            border-radius: 5px;
            padding: 20px;
            margin-bottom: 15px;
        }
        .resolution-description {
            font-weight: 600;
            color: #155724;
            margin-bottom: 10px;
        }
        .solution-steps {
            margin: 10px 0;
        }
        .solution-steps li {
            margin: 8px 0;
            padding-left: 10px;
            line-height: 1.6;
        }
        .kb-articles {
            margin-top: 10px;
            padding: 10px;
            background: #e7f3ff;
            border-radius: 4px;
            line-height: 1.8;
        }
        .kb-articles a {
            color: #004085;
            text-decoration: none;
            display: block;
            padding: 3px 0;
        }
        .kb-articles a:hover {
            text-decoration: underline;
            color: #002752;
        }
        .kb-articles strong {
            color: #004085;
        }
        .prevention-tip {
            margin-top: 10px;
            padding: 10px;
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            border-radius: 4px;
            font-style: italic;
        }
        .occurrences {
            margin-top: 15px;
        }
        .occurrence-item {
            padding: 8px;
            background: #f8f9fa;
            border-left: 3px solid #6c757d;
            margin: 5px 0;
            font-size: 0.85em;
        }
        .footer {
            background: #f8f9fa;
            padding: 20px 40px;
            text-align: center;
            color: #6c757d;
            border-top: 1px solid #dee2e6;
        }
        .priority-legend {
            display: flex;
            gap: 20px;
            justify-content: center;
            margin-bottom: 30px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
        }
        .legend-item {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .legend-color {
            width: 20px;
            height: 20px;
            border-radius: 3px;
        }
        @media print {
            body { background: white; padding: 0; }
            .issue-card { page-break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 SolarWinds Log Analysis Report</h1>
            <div class="subtitle">Generated: """ + datetime.now().strftime('%B %d, %Y at %I:%M %p') + """</div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">""" + str(len(results)) + """</div>
                <div class="stat-label">Total Issues Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">""" + str(log_stats.get('files_analyzed', 0)) + """</div>
                <div class="stat-label">Log Files Analyzed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">""" + str(log_stats.get('critical_count', 0)) + """</div>
                <div class="stat-label">Critical Issues</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">""" + str(log_stats.get('error_count', 0)) + """</div>
                <div class="stat-label">Errors</div>
            </div>
        </div>
        
        <div class="content">
            <div class="priority-legend">
                <div class="legend-item">
                    <div class="legend-color" style="background: #dc3545;"></div>
                    <span>Priority 1 - Critical</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #fd7e14;"></div>
                    <span>Priority 2 - High</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #ffc107;"></div>
                    <span>Priority 3 - Medium</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #28a745;"></div>
                    <span>Priority 4 - Low</span>
                </div>
            </div>
"""
        
        for idx, result in enumerate(results, 1):
            issue = result['issue']
            priority = result['priority']
            
            html += f"""
            <div class="issue-card priority-{priority}">
                <div class="issue-header">
                    <div class="issue-title">Issue #{idx}: {issue['category'].replace('_', ' ').title()}</div>
                    <div class="badges">
                        <span class="badge {issue['severity'].lower()}">{issue['severity']}</span>
                        <span class="badge count">{issue['count']} occurrences</span>
                        <span class="badge category">{issue['category']}</span>
                    </div>
                </div>
                
                <div class="issue-details">
                    {issue['sample_message'][:500]}{'...' if len(issue['sample_message']) > 500 else ''}
                </div>
                
                <div class="meta-info">
                    <div class="meta-item">
                        <span class="meta-label">First Occurrence</span>
                        <span class="meta-value">{issue['first_occurrence']}</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Last Occurrence</span>
                        <span class="meta-value">{issue['last_occurrence']}</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Affected Files</span>
                        <span class="meta-value">{', '.join(issue['affected_files'][:3])}</span>
                    </div>
                    {'<div class="meta-item"><span class="meta-label">Exception Type</span><span class="meta-value">' + issue['exception_type'] + '</span></div>' if issue.get('exception_type') else ''}
                </div>
                
                <div class="resolution-section">
                    <div class="resolution-title">📋 Recommended Solutions</div>
"""
            
            for resolution in result['resolutions']:
                html += f"""
                    <div class="resolution-box">
                        <div class="resolution-description">{resolution['description']}</div>
                        <ol class="solution-steps">
"""
                for step in resolution['solutions']:
                    html += f"                            <li>{step}</li>\n"
                
                html += """                        </ol>
"""
                
                if resolution.get('kb_articles'):
                    html += """                        <div class="kb-articles">
                            <strong>📚 SolarWinds Knowledge Base Articles:</strong><br>
"""
                    for kb in resolution['kb_articles']:
                        if isinstance(kb, dict):
                            html += f"""                            <a href="{kb['url']}" target="_blank" style="color: #004085; text-decoration: none;">• {kb['title']}</a><br>
"""
                        else:
                            html += f"""                            • {kb}<br>
"""
                    html += """                        </div>
"""
                
                if resolution.get('prevention'):
                    html += f"""                        <div class="prevention-tip">
                            <strong>💡 Prevention:</strong> {resolution['prevention']}
                        </div>
"""
                
                html += """                    </div>
"""
            
            # Add sample occurrences
            if issue.get('all_occurrences'):
                html += """                    <div class="occurrences">
                        <strong>Recent Occurrences:</strong>
"""
                for occ in issue['all_occurrences'][:5]:
                    html += f"""                        <div class="occurrence-item">
                            <strong>{occ['timestamp']}</strong> - {occ['file']} (Line {occ['line_number']})
                        </div>
"""
                html += """                    </div>
"""
            
            html += """                </div>
            </div>
"""
        
        html += """
        </div>
        
        <div class="footer">
            <p>SolarWinds Log Analyzer - Automated Issue Detection & Resolution</p>
            <p>For additional support, visit SolarWinds Support Portal or contact Technical Support</p>
        </div>
    </div>
</body>
</html>
"""
        return html


class SolarWindsLogAnalyzer:
    """Main application class"""
    
    def __init__(self, hours_back: int = 24):
        self.hours_back = hours_back
        self.path_manager = LogPathManager()
        self.parser = LogParser()
        self.aggregator = IssueAggregator()
        self.resolver = ResolutionFinder()
        self.report_generator = ReportGenerator()
    
    def analyze(self) -> Tuple[List[Dict], Dict]:
        """Run complete analysis"""
        logging.info("=" * 70)
        logging.info("Starting SolarWinds Log Analysis")
        logging.info("=" * 70)
        
        # Get log files
        logging.info(f"\n📁 Scanning for log files modified in last {self.hours_back} hours...")
        log_files = self.path_manager.get_all_log_files(self.hours_back)
        
        if not log_files:
            logging.warning("No log files found! Check if paths are correct.")
            return [], {'files_analyzed': 0}
        
        # Parse all log files
        all_issues = []
        files_analyzed = 0
        
        for category, files in log_files.items():
            logging.info(f"\n🔍 Analyzing {category} logs...")
            for file_path in files:
                logging.info(f"   Processing: {os.path.basename(file_path)}")
                issues = self.parser.parse_log_file(file_path)
                all_issues.extend(issues)
                files_analyzed += 1
        
        logging.info(f"\n✅ Found {len(all_issues)} total issue entries")
        
        # Aggregate similar issues
        logging.info("\n📊 Aggregating and categorizing issues...")
        aggregated_issues = self.aggregator.aggregate_issues(all_issues)
        logging.info(f"✅ Identified {len(aggregated_issues)} unique issue patterns")
        
        # Find resolutions
        logging.info("\n🔧 Finding resolutions for issues...")
        results = []
        for issue in aggregated_issues:
            resolution = self.resolver.find_resolution(issue)
            results.append(resolution)
        
        # Calculate statistics
        stats = {
            'files_analyzed': files_analyzed,
            'total_issues': len(all_issues),
            'unique_patterns': len(aggregated_issues),
            'critical_count': sum(1 for i in aggregated_issues if i['severity'] == 'CRITICAL'),
            'error_count': sum(1 for i in aggregated_issues if i['severity'] == 'ERROR'),
            'warning_count': sum(1 for i in aggregated_issues if i['severity'] == 'WARNING')
        }
        
        logging.info("\n" + "=" * 70)
        logging.info("Analysis Statistics:")
        logging.info(f"  Files Analyzed: {stats['files_analyzed']}")
        logging.info(f"  Total Issues: {stats['total_issues']}")
        logging.info(f"  Unique Patterns: {stats['unique_patterns']}")
        logging.info(f"  Critical: {stats['critical_count']}")
        logging.info(f"  Errors: {stats['error_count']}")
        logging.info(f"  Warnings: {stats['warning_count']}")
        logging.info("=" * 70)
        
        return results, stats
    
    def generate_report(self, results: List[Dict], stats: Dict, output_file: str = None):
        """Generate HTML report"""
        if not output_file:
            output_file = f"SolarWinds_Analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        logging.info(f"\n📝 Generating report: {output_file}")
        html_content = self.report_generator.generate_html_report(results, stats)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logging.info(f"✅ Report saved successfully!")
        return output_file
    
    def print_summary(self, results: List[Dict]):
        """Print console summary of top issues"""
        print("\n" + "=" * 70)
        print("🔥 TOP 10 ISSUES REQUIRING ATTENTION")
        print("=" * 70)
        
        for idx, result in enumerate(results[:10], 1):
            issue = result['issue']
            print(f"\n{idx}. [{issue['severity']}] {issue['category'].replace('_', ' ').title()}")
            print(f"   Count: {issue['count']} occurrences")
            print(f"   Priority: {result['priority']}")
            print(f"   Files: {', '.join(issue['affected_files'][:2])}")
            print(f"   Message: {issue['sample_message'][:100]}...")


def main():
    """Main entry point"""
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║        SolarWinds Log Analyzer & Resolution Finder v2.0              ║
║                                                                      ║
║  Automatically analyzes SolarWinds logs, identifies issues,          ║
║  and provides step-by-step resolutions                               ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
    """)
    
    # Get time range
    while True:
        try:
            hours = input("\nAnalyze logs from last X hours [default: 24]: ").strip()
            hours = int(hours) if hours else 24
            break
        except ValueError:
            print("Please enter a valid number")
    
    # Create analyzer
    analyzer = SolarWindsLogAnalyzer(hours_back=hours)
    
    try:
        # Run analysis
        results, stats = analyzer.analyze()
        
        if not results:
            print("\n✅ No issues found in the specified time period!")
            return
        
        # Print summary to console
        analyzer.print_summary(results)
        
        # Generate report
        report_file = analyzer.generate_report(results, stats)
        
        print(f"\n{'=' * 70}")
        print(f"✅ Analysis Complete!")
        print(f"📄 Full report saved to: {report_file}")
        print(f"💡 Open the HTML file in your browser for detailed resolutions")
        print(f"{'=' * 70}")
        
        # Ask if user wants to open report
        open_report = input("\nOpen report in browser? (y/n): ").strip().lower()
        if open_report == 'y':
            import webbrowser
            webbrowser.open(report_file)
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Analysis cancelled by user")
    except Exception as e:
        logging.error(f"Error during analysis: {e}", exc_info=True)
        print(f"\n❌ Error: {e}")
        print("Check solarwinds_log_analyzer.log for details")


if __name__ == "__main__":
    main(), '', error_text)  # Remove file paths
                if len(error_text) > 15:
                    return error_text[:200]
        
        # Extract key terms
        key_terms = []
        
        # Look for specific error codes or IDs
        error_codes = re.findall(r'\b(?:error|code|id)[\s:-]*(\d{3,5})\b', message, re.IGNORECASE)
        if error_codes:
            key_terms.extend([f"error {code}" for code in error_codes[:2]])
        
        # Extract exception types
        exceptions = re.findall(r'([A-Z][a-zA-Z]+(?:Exception|Error))', message)
        if exceptions:
            key_terms.extend(exceptions[:2])
        
        # Key error phrases (multi-word)
        important_phrases = [
            'unable to load', 'failed to connect', 'connection timeout', 
            'access denied', 'permission denied', 'authentication failed',
            'service unavailable', 'database error', 'sql timeout',
            'out of memory', 'disk space', 'license expired',
            'certificate invalid', 'polling failed', 'node unreachable'
        ]
        
        message_lower = message.lower()
        for phrase in important_phrases:
            if phrase in message_lower:
                key_terms.append(phrase)
        
        # Single important terms
        important_terms = ['timeout', 'deadlock', 'failed', 'connection', 'authentication',
                          'permission', 'denied', 'polling', 'snmp', 'wmi', 'sql', 
                          'service', 'license', 'certificate', 'memory', 'disk',
                          'unreachable', 'unavailable', 'invalid']
        
        words = message_lower.split()
        for term in important_terms:
            if term in words:
                key_terms.append(term)
        
        # If we have terms, create a search query
        if key_terms:
            # Remove duplicates while preserving order
            seen = set()
            unique_terms = []
            for term in key_terms:
                if term.lower() not in seen:
                    seen.add(term.lower())
                    unique_terms.append(term)
            
            search_query = ' '.join(unique_terms[:5])
        else:
            # Use first meaningful part of message
            words = message.split()
            meaningful_words = [w for w in words if len(w) > 3 and not w.isdigit()]
            search_query = ' '.join(meaningful_words[:10])
        
        return search_query.strip()
    
    RESOLUTION_DATABASE = {
        'sql_error': {
            'Deadlock': {
                'description': 'SQL deadlock detected',
                'solutions': [
                    'Review queries in BusinessLayerHost.log for long-running queries',
                    'Check SQL Server Activity Monitor for blocking sessions',
                    'Run: SELECT * FROM sys.dm_tran_locks to identify locked resources',
                    'Consider enabling Read Committed Snapshot Isolation',
                    'Review database maintenance windows to avoid conflicts',
                    'Restart SolarWinds services during low-activity periods'
                ],
                'kb_articles': ['KB Article: How to Resolve SQL Deadlocks in SolarWinds'],
                'prevention': 'Schedule database maintenance during off-peak hours'
            },
            'Connection Failed': {
                'description': 'Cannot connect to SQL Server',
                'solutions': [
                    'Verify SQL Server service is running',
                    'Check SQL Server Configuration Manager for network protocols',
                    'Test connection: sqlcmd -S <server> -U <user> -P <password>',
                    'Verify firewall allows port 1433',
                    'Check SolarWinds connection string in SolarWinds.Orion.Core.dll.config',
                    'Review SQL Server error logs for authentication issues'
                ],
                'kb_articles': ['Troubleshooting SQL Connectivity'],
                'prevention': 'Monitor SQL Server health and set up alerts'
            },
            'Transaction Log Full': {
                'description': 'SQL transaction log is full',
                'solutions': [
                    'Check database recovery model: SELECT name, recovery_model_desc FROM sys.databases',
                    'Backup transaction log: BACKUP LOG [SolarWindsOrion] TO DISK',
                    'Shrink log file: DBCC SHRINKFILE (SolarWindsOrion_log, 1024)',
                    'Review database maintenance plan',
                    'Consider switching to Simple recovery model if not using log backups',
                    'Run Database Maintenance in Configuration Wizard'
                ],
                'kb_articles': ['Managing SolarWinds Database Size'],
                'prevention': 'Schedule regular transaction log backups'
            }
        },
        'connection_error': {
            'Network Unreachable': {
                'description': 'Unable to reach remote devices',
                'solutions': [
                    'Verify network connectivity with ping and traceroute',
                    'Check firewall rules on both SolarWinds server and target',
                    'Verify VLANs and routing configuration',
                    'Check if polling engine is on correct network segment',
                    'Test SNMP: snmpwalk -v2c -c <community> <host>',
                    'Review routing tables and ACLs'
                ],
                'kb_articles': ['Network Connectivity Troubleshooting Guide'],
                'prevention': 'Implement redundant polling engines'
            },
            'Timeout': {
                'description': 'Connection or operation timeout',
                'solutions': [
                    'Increase timeout values in Orion.Web.config',
                    'Check network latency with ping -t',
                    'Review polling intervals - reduce frequency if needed',
                    'Verify target device is not overloaded',
                    'Check for network packet loss',
                    'Review BusinessLayerHost.log for slow queries'
                ],
                'kb_articles': ['Adjusting Timeout Settings'],
                'prevention': 'Optimize polling intervals based on network capacity'
            }
        },
        'authentication_error': {
            'Access Denied': {
                'description': 'Permission or credential issues',
                'solutions': [
                    'Run OrionPermissionChecker.exe to verify permissions',
                    'Verify credentials in Node Management',
                    'Check Windows Event Viewer for authentication failures',
                    'Ensure service account has required permissions',
                    'For SNMP: verify community strings match',
                    'For WMI: Run wmimgmt.msc and check DCOM permissions',
                    'Reset credentials: Settings > Manage Nodes > Edit Properties'
                ],
                'kb_articles': ['SolarWinds Service Account Requirements', 'SNMP Configuration Guide'],
                'prevention': 'Use group-managed service accounts and document credential rotation'
            },
            'Login Failed': {
                'description': 'Authentication failure',
                'solutions': [
                    'Verify account is not locked: net user <username> /domain',
                    'Check password expiration: net user <username>',
                    'Ensure account has proper SQL permissions',
                    'Verify SolarWinds service account permissions',
                    'Check Active Directory group membership',
                    'Review IIS application pool identity'
                ],
                'kb_articles': ['Configuring Service Accounts'],
                'prevention': 'Set passwords to never expire for service accounts'
            }
        },
        'service_error': {
            'Service Stopped': {
                'description': 'SolarWinds service not running',
                'solutions': [
                    'Check Windows Event Viewer for crash details',
                    'Review service dependencies: sc qc <servicename>',
                    'Restart service: net start "SolarWinds <ServiceName>"',
                    'Check BusinessLayerHost.log for errors before crash',
                    'Verify SQL Server connectivity',
                    'Increase service timeout: sc config <service> start=delayed-auto',
                    'Check for .NET Framework issues'
                ],
                'kb_articles': ['Troubleshooting Service Failures'],
                'prevention': 'Monitor services with SolarWinds SAM'
            }
        },
        'polling_error': {
            'SNMP Timeout': {
                'description': 'SNMP polling failures',
                'solutions': [
                    'Verify SNMP service is running on target device',
                    'Test SNMP manually: snmpget -v2c -c <community> <host> sysDescr.0',
                    'Check SNMP community string is correct',
                    'Verify firewall allows UDP 161',
                    'Increase SNMP timeout in Polling Settings',
                    'Check device CPU usage - SNMP may be slow',
                    'Review MIB compatibility'
                ],
                'kb_articles': ['SNMP Polling Best Practices'],
                'prevention': 'Use SNMPv3 for better reliability and security'
            },
            'WMI Error': {
                'description': 'WMI polling failures for Windows devices',
                'solutions': [
                    'Verify WMI service: Get-Service Winmgmt',
                    'Test WMI: wmic /node:<host> /user:<user> computersystem get name',
                    'Rebuild WMI repository: winmgmt /resetrepository',
                    'Check DCOM permissions: dcomcnfg',
                    'Verify firewall allows port 135 and dynamic RPC ports',
                    'Run OrionPermissionChecker for WMI validation',
                    'Review security log for audit failures'
                ],
                'kb_articles': ['WMI Troubleshooting Guide', 'Windows Firewall Configuration'],
                'prevention': 'Regular WMI health checks and monitoring'
            }
        },
        'memory_error': {
            'Out of Memory': {
                'description': 'Application or system memory exhaustion',
                'solutions': [
                    'Check available RAM: Get-Counter "\\Memory\\Available MBytes"',
                    'Restart SolarWinds services to free memory',
                    'Review BusinessLayerHost.log for memory leaks',
                    'Check Task Manager for memory-consuming processes',
                    'Increase server RAM (minimum 16GB recommended)',
                    'Reduce polling frequency for non-critical nodes',
                    'Clear IIS application pool recycling',
                    'Review custom SQL queries and reports'
                ],
                'kb_articles': ['SolarWinds Performance Tuning', 'Memory Requirements'],
                'prevention': 'Monitor memory usage and plan capacity upgrades'
            }
        },
        'web_error': {
            'HTTP 500': {
                'description': 'Internal server error',
                'solutions': [
                    'Check OrionWeb.log for detailed error messages',
                    'Review IIS logs: C:\\inetpub\\logs\\LogFiles',
                    'Verify application pool is running',
                    'Check .NET Framework version compatibility',
                    'Clear browser cache and cookies',
                    'Recycle IIS application pool: iisreset',
                    'Verify database connectivity from web server',
                    'Check SWIS service status'
                ],
                'kb_articles': ['Web Console Troubleshooting'],
                'prevention': 'Regular IIS health monitoring'
            }
        },
        'license_error': {
            'License Expired': {
                'description': 'SolarWinds license issue',
                'solutions': [
                    'Check license status: Settings > License Manager',
                    'Contact SolarWinds support for license renewal',
                    'Import new license file if available',
                    'Verify license count matches deployed elements',
                    'Check for evaluation/trial expiration',
                    'Review maintenance contract status'
                ],
                'kb_articles': ['License Management Guide'],
                'prevention': 'Set calendar reminders 30 days before expiration'
            }
        },
        'job_error': {
            'Job Failed': {
                'description': 'Scheduled job or task failure',
                'solutions': [
                    'Review JobEngine logs for specific error details',
                    'Check job schedule and dependencies',
                    'Verify job account permissions',
                    'Test job manually: Settings > Manage Jobs',
                    'Check database connectivity during job execution',
                    'Review job query syntax for errors',
                    'Verify adequate system resources during job runtime'
                ],
                'kb_articles': ['Job Engine Troubleshooting'],
                'prevention': 'Schedule intensive jobs during maintenance windows'
            }
        },
        'ha_error': {
            'Failover Failed': {
                'description': 'High Availability failover issues',
                'solutions': [
                    'Check HA logs for specific failure reason',
                    'Verify network connectivity between HA nodes',
                    'Test database replication status',
                    'Check Windows Failover Cluster status',
                    'Verify shared storage accessibility',
                    'Review HA configuration: Settings > High Availability',
                    'Ensure both nodes meet system requirements',
                    'Check for Windows updates or patches on nodes'
                ],
                'kb_articles': ['High Availability Configuration Guide', 'HA Troubleshooting'],
                'prevention': 'Regular HA testing and monitoring'
            }
        },
        'certificate_error': {
            'Certificate Expired': {
                'description': 'SSL/TLS certificate issues',
                'solutions': [
                    'Check certificate expiration: Get-ChildItem Cert:\\LocalMachine\\My',
                    'Renew certificate through Certificate Manager (certmgr.msc)',
                    'Update certificate binding in IIS',
                    'Verify certificate chain is complete',
                    'Check certificate permissions for service account',
                    'Update certificate in SolarWinds: Settings > Certificates',
                    'Clear SSL cache: certutil -urlcache * delete'
                ],
                'kb_articles': ['SSL Certificate Management'],
                'prevention': 'Monitor certificate expiration dates'
            }
        },
        'configuration_error': {
            'Configuration Invalid': {
                'description': 'Configuration file or setting issues',
                'solutions': [
                    'Review ConfigurationWizard.log for specific errors',
                    'Validate XML configuration files',
                    'Compare with backup configuration files',
                    'Re-run Configuration Wizard',
                    'Check file permissions on configuration directories',
                    'Verify database schema version matches application version',
                    'Review recent configuration changes'
                ],
                'kb_articles': ['Configuration Best Practices'],
                'prevention': 'Backup configurations before changes'
            }
        }
    }
    
    def find_resolution(self, issue: Dict) -> Dict:
        """Find resolution for a specific issue"""
        category = issue['category']
        message = issue['sample_message']
        
        resolutions = []
        kb_articles = []
        
        # Search SolarWinds KB for real articles
        logging.info(f"Searching KB for: {category}")
        kb_articles = self.search_solarwinds_kb(message)
        
        if category in self.RESOLUTION_DATABASE:
            # Try to match specific error type
            for error_type, resolution_data in self.RESOLUTION_DATABASE[category].items():
                if any(keyword.lower() in message.lower() for keyword in error_type.split()):
                    # Merge KB articles with resolution data
                    resolution_copy = resolution_data.copy()
                    if kb_articles:
                        resolution_copy['kb_articles'] = kb_articles
                    resolutions.append(resolution_copy)
            
            # If no specific match, provide generic resolution for category
            if not resolutions:
                first_resolution = list(self.RESOLUTION_DATABASE[category].values())[0].copy()
                if kb_articles:
                    first_resolution['kb_articles'] = kb_articles
                resolutions.append(first_resolution)
        else:
            # Generic troubleshooting steps
            resolutions.append({
                'description': 'General troubleshooting required',
                'solutions': [
                    'Review the specific log file for detailed error messages',
                    'Check Windows Event Viewer for system-level errors',
                    'Verify all SolarWinds services are running',
                    'Test database connectivity',
                    'Review recent changes to the environment',
                    'Check SolarWinds Support portal for similar issues',
                    'Contact SolarWinds Technical Support if issue persists'
                ],
                'kb_articles': kb_articles if kb_articles else [],
                'prevention': 'Regular system health checks'
            })
        
        return {
            'issue': issue,
            'resolutions': resolutions,
            'priority': self._calculate_priority(issue)
        }
    
    def _calculate_priority(self, issue: Dict) -> int:
        """Calculate issue priority (1=highest, 5=lowest)"""
        severity_priority = {
            'CRITICAL': 1,
            'ERROR': 2,
            'WARNING': 3,
            'INFO': 4
        }
        
        base_priority = severity_priority.get(issue['severity'], 4)
        
        # Adjust based on frequency
        if issue['count'] > 100:
            base_priority = max(1, base_priority - 1)
        elif issue['count'] > 10:
            base_priority = max(1, base_priority - 0.5)
        
        return int(base_priority)


class ReportGenerator:
    """Generates comprehensive HTML reports"""
    
    def generate_html_report(self, results: List[Dict], log_stats: Dict) -> str:
        """Generate detailed HTML report"""
        
        html = """
<!DOCTYPE html>
<html>
<head>
    <title>SolarWinds Log Analysis Report</title>
    <meta charset="UTF-8">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .header .subtitle {
            font-size: 1.1em;
            opacity: 0.9;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px 40px;
            background: #f8f9fa;
            border-bottom: 1px solid #dee2e6;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #2a5298;
        }
        .stat-label {
            color: #6c757d;
            margin-top: 5px;
            font-size: 0.9em;
        }
        .content {
            padding: 40px;
        }
        .issue-card {
            background: white;
            border: 1px solid #dee2e6;
            border-left: 5px solid #dc3545;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }
        .issue-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        .issue-card.priority-1 { border-left-color: #dc3545; }
        .issue-card.priority-2 { border-left-color: #fd7e14; }
        .issue-card.priority-3 { border-left-color: #ffc107; }
        .issue-card.priority-4 { border-left-color: #28a745; }
        .issue-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
        }
        .issue-title {
            font-size: 1.4em;
            color: #212529;
            font-weight: 600;
        }
        .badges {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        .badge {
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            display: inline-block;
        }
        .badge.critical { background: #dc3545; color: white; }
        .badge.error { background: #fd7e14; color: white; }
        .badge.warning { background: #ffc107; color: #212529; }
        .badge.info { background: #17a2b8; color: white; }
        .badge.count { background: #6c757d; color: white; }
        .badge.category { background: #007bff; color: white; }
        .issue-details {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
        }
        .meta-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 15px 0;
            font-size: 0.9em;
        }
        .meta-item {
            display: flex;
            flex-direction: column;
        }
        .meta-label {
            color: #6c757d;
            font-size: 0.85em;
            margin-bottom: 3px;
        }
        .meta-value {
            color: #212529;
            font-weight: 500;
        }
        .resolution-section {
            margin-top: 20px;
            padding-top: 20px;
            border-top: 2px solid #e9ecef;
        }
        .resolution-title {
            font-size: 1.2em;
            color: #28a745;
            margin-bottom: 15px;
            font-weight: 600;
        }
        .resolution-box {
            background: #f0fff4;
            border: 1px solid #c3e6cb;
            border-radius: 5px;
            padding: 20px;
            margin-bottom: 15px;
        }
        .resolution-description {
            font-weight: 600;
            color: #155724;
            margin-bottom: 10px;
        }
        .solution-steps {
            margin: 10px 0;
        }
        .solution-steps li {
            margin: 8px 0;
            padding-left: 10px;
            line-height: 1.6;
        }
        .kb-articles {
            margin-top: 10px;
            padding: 10px;
            background: #e7f3ff;
            border-radius: 4px;
            line-height: 1.8;
        }
        .kb-articles a {
            color: #004085;
            text-decoration: none;
            display: block;
            padding: 3px 0;
        }
        .kb-articles a:hover {
            text-decoration: underline;
            color: #002752;
        }
        .kb-articles strong {
            color: #004085;
        }
        .prevention-tip {
            margin-top: 10px;
            padding: 10px;
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            border-radius: 4px;
            font-style: italic;
        }
        .occurrences {
            margin-top: 15px;
        }
        .occurrence-item {
            padding: 8px;
            background: #f8f9fa;
            border-left: 3px solid #6c757d;
            margin: 5px 0;
            font-size: 0.85em;
        }
        .footer {
            background: #f8f9fa;
            padding: 20px 40px;
            text-align: center;
            color: #6c757d;
            border-top: 1px solid #dee2e6;
        }
        .priority-legend {
            display: flex;
            gap: 20px;
            justify-content: center;
            margin-bottom: 30px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
        }
        .legend-item {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .legend-color {
            width: 20px;
            height: 20px;
            border-radius: 3px;
        }
        @media print {
            body { background: white; padding: 0; }
            .issue-card { page-break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 SolarWinds Log Analysis Report</h1>
            <div class="subtitle">Generated: """ + datetime.now().strftime('%B %d, %Y at %I:%M %p') + """</div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">""" + str(len(results)) + """</div>
                <div class="stat-label">Total Issues Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">""" + str(log_stats.get('files_analyzed', 0)) + """</div>
                <div class="stat-label">Log Files Analyzed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">""" + str(log_stats.get('critical_count', 0)) + """</div>
                <div class="stat-label">Critical Issues</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">""" + str(log_stats.get('error_count', 0)) + """</div>
                <div class="stat-label">Errors</div>
            </div>
        </div>
        
        <div class="content">
            <div class="priority-legend">
                <div class="legend-item">
                    <div class="legend-color" style="background: #dc3545;"></div>
                    <span>Priority 1 - Critical</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #fd7e14;"></div>
                    <span>Priority 2 - High</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #ffc107;"></div>
                    <span>Priority 3 - Medium</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #28a745;"></div>
                    <span>Priority 4 - Low</span>
                </div>
            </div>
"""
        
        for idx, result in enumerate(results, 1):
            issue = result['issue']
            priority = result['priority']
            
            html += f"""
            <div class="issue-card priority-{priority}">
                <div class="issue-header">
                    <div class="issue-title">Issue #{idx}: {issue['category'].replace('_', ' ').title()}</div>
                    <div class="badges">
                        <span class="badge {issue['severity'].lower()}">{issue['severity']}</span>
                        <span class="badge count">{issue['count']} occurrences</span>
                        <span class="badge category">{issue['category']}</span>
                    </div>
                </div>
                
                <div class="issue-details">
                    {issue['sample_message'][:500]}{'...' if len(issue['sample_message']) > 500 else ''}
                </div>
                
                <div class="meta-info">
                    <div class="meta-item">
                        <span class="meta-label">First Occurrence</span>
                        <span class="meta-value">{issue['first_occurrence']}</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Last Occurrence</span>
                        <span class="meta-value">{issue['last_occurrence']}</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Affected Files</span>
                        <span class="meta-value">{', '.join(issue['affected_files'][:3])}</span>
                    </div>
                    {'<div class="meta-item"><span class="meta-label">Exception Type</span><span class="meta-value">' + issue['exception_type'] + '</span></div>' if issue.get('exception_type') else ''}
                </div>
                
                <div class="resolution-section">
                    <div class="resolution-title">📋 Recommended Solutions</div>
"""
            
            for resolution in result['resolutions']:
                html += f"""
                    <div class="resolution-box">
                        <div class="resolution-description">{resolution['description']}</div>
                        <ol class="solution-steps">
"""
                for step in resolution['solutions']:
                    html += f"                            <li>{step}</li>\n"
                
                html += """                        </ol>
"""
                
                if resolution.get('kb_articles'):
                    html += """                        <div class="kb-articles">
                            <strong>📚 SolarWinds Knowledge Base Articles:</strong><br>
"""
                    for kb in resolution['kb_articles']:
                        if isinstance(kb, dict):
                            html += f"""                            <a href="{kb['url']}" target="_blank" style="color: #004085; text-decoration: none;">• {kb['title']}</a><br>
"""
                        else:
                            html += f"""                            • {kb}<br>
"""
                    html += """                        </div>
"""
                
                if resolution.get('prevention'):
                    html += f"""                        <div class="prevention-tip">
                            <strong>💡 Prevention:</strong> {resolution['prevention']}
                        </div>
"""
                
                html += """                    </div>
"""
            
            # Add sample occurrences
            if issue.get('all_occurrences'):
                html += """                    <div class="occurrences">
                        <strong>Recent Occurrences:</strong>
"""
                for occ in issue['all_occurrences'][:5]:
                    html += f"""                        <div class="occurrence-item">
                            <strong>{occ['timestamp']}</strong> - {occ['file']} (Line {occ['line_number']})
                        </div>
"""
                html += """                    </div>
"""
            
            html += """                </div>
            </div>
"""
        
        html += """
        </div>
        
        <div class="footer">
            <p>SolarWinds Log Analyzer - Automated Issue Detection & Resolution</p>
            <p>For additional support, visit SolarWinds Support Portal or contact Technical Support</p>
        </div>
    </div>
</body>
</html>
"""
        return html


class SolarWindsLogAnalyzer:
    """Main application class"""
    
    def __init__(self, hours_back: int = 24):
        self.hours_back = hours_back
        self.path_manager = LogPathManager()
        self.parser = LogParser()
        self.aggregator = IssueAggregator()
        self.resolver = ResolutionFinder()
        self.report_generator = ReportGenerator()
    
    def analyze(self) -> Tuple[List[Dict], Dict]:
        """Run complete analysis"""
        logging.info("=" * 70)
        logging.info("Starting SolarWinds Log Analysis")
        logging.info("=" * 70)
        
        # Get log files
        logging.info(f"\n📁 Scanning for log files modified in last {self.hours_back} hours...")
        log_files = self.path_manager.get_all_log_files(self.hours_back)
        
        if not log_files:
            logging.warning("No log files found! Check if paths are correct.")
            return [], {'files_analyzed': 0}
        
        # Parse all log files
        all_issues = []
        files_analyzed = 0
        
        for category, files in log_files.items():
            logging.info(f"\n🔍 Analyzing {category} logs...")
            for file_path in files:
                logging.info(f"   Processing: {os.path.basename(file_path)}")
                issues = self.parser.parse_log_file(file_path)
                all_issues.extend(issues)
                files_analyzed += 1
        
        logging.info(f"\n✅ Found {len(all_issues)} total issue entries")
        
        # Aggregate similar issues
        logging.info("\n📊 Aggregating and categorizing issues...")
        aggregated_issues = self.aggregator.aggregate_issues(all_issues)
        logging.info(f"✅ Identified {len(aggregated_issues)} unique issue patterns")
        
        # Find resolutions
        logging.info("\n🔧 Finding resolutions for issues...")
        results = []
        for issue in aggregated_issues:
            resolution = self.resolver.find_resolution(issue)
            results.append(resolution)
        
        # Calculate statistics
        stats = {
            'files_analyzed': files_analyzed,
            'total_issues': len(all_issues),
            'unique_patterns': len(aggregated_issues),
            'critical_count': sum(1 for i in aggregated_issues if i['severity'] == 'CRITICAL'),
            'error_count': sum(1 for i in aggregated_issues if i['severity'] == 'ERROR'),
            'warning_count': sum(1 for i in aggregated_issues if i['severity'] == 'WARNING')
        }
        
        logging.info("\n" + "=" * 70)
        logging.info("Analysis Statistics:")
        logging.info(f"  Files Analyzed: {stats['files_analyzed']}")
        logging.info(f"  Total Issues: {stats['total_issues']}")
        logging.info(f"  Unique Patterns: {stats['unique_patterns']}")
        logging.info(f"  Critical: {stats['critical_count']}")
        logging.info(f"  Errors: {stats['error_count']}")
        logging.info(f"  Warnings: {stats['warning_count']}")
        logging.info("=" * 70)
        
        return results, stats
    
    def generate_report(self, results: List[Dict], stats: Dict, output_file: str = None):
        """Generate HTML report"""
        if not output_file:
            output_file = f"SolarWinds_Analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        logging.info(f"\n📝 Generating report: {output_file}")
        html_content = self.report_generator.generate_html_report(results, stats)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logging.info(f"✅ Report saved successfully!")
        return output_file
    
    def print_summary(self, results: List[Dict]):
        """Print console summary of top issues"""
        print("\n" + "=" * 70)
        print("🔥 TOP 10 ISSUES REQUIRING ATTENTION")
        print("=" * 70)
        
        for idx, result in enumerate(results[:10], 1):
            issue = result['issue']
            print(f"\n{idx}. [{issue['severity']}] {issue['category'].replace('_', ' ').title()}")
            print(f"   Count: {issue['count']} occurrences")
            print(f"   Priority: {result['priority']}")
            print(f"   Files: {', '.join(issue['affected_files'][:2])}")
            print(f"   Message: {issue['sample_message'][:100]}...")


def main():
    """Main entry point"""
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║        SolarWinds Log Analyzer & Resolution Finder v2.0              ║
║                                                                      ║
║  Automatically analyzes SolarWinds logs, identifies issues,          ║
║  and provides step-by-step resolutions                               ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
    """)
    
    # Get time range
    while True:
        try:
            hours = input("\nAnalyze logs from last X hours [default: 24]: ").strip()
            hours = int(hours) if hours else 24
            break
        except ValueError:
            print("Please enter a valid number")
    
    # Create analyzer
    analyzer = SolarWindsLogAnalyzer(hours_back=hours)
    
    try:
        # Run analysis
        results, stats = analyzer.analyze()
        
        if not results:
            print("\n✅ No issues found in the specified time period!")
            return
        
        # Print summary to console
        analyzer.print_summary(results)
        
        # Generate report
        report_file = analyzer.generate_report(results, stats)
        
        print(f"\n{'=' * 70}")
        print(f"✅ Analysis Complete!")
        print(f"📄 Full report saved to: {report_file}")
        print(f"💡 Open the HTML file in your browser for detailed resolutions")
        print(f"{'=' * 70}")
        
        # Ask if user wants to open report
        open_report = input("\nOpen report in browser? (y/n): ").strip().lower()
        if open_report == 'y':
            import webbrowser
            webbrowser.open(report_file)
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Analysis cancelled by user")
    except Exception as e:
        logging.error(f"Error during analysis: {e}", exc_info=True)
        print(f"\n❌ Error: {e}")
        print("Check solarwinds_log_analyzer.log for details")


if __name__ == "__main__":
    main()