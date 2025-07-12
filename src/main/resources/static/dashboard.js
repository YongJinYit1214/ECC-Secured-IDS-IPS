// Global variables
let authToken = null;
let currentAlert = null;
const API_BASE = '/api/v1';

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    // Check if user is already logged in
    authToken = localStorage.getItem('authToken');
    if (authToken) {
        validateToken();
    } else {
        showLogin();
    }
    
    // Setup event listeners
    setupEventListeners();
});

function setupEventListeners() {
    // Login form
    document.getElementById('loginForm').addEventListener('submit', handleLogin);
    
    // Navigation
    document.querySelectorAll('[data-section]').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            showSection(this.dataset.section);
            
            // Update active nav
            document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
            this.classList.add('active');
        });
    });
    
    // Block IP form
    document.getElementById('blockIpForm').addEventListener('submit', function(e) {
        e.preventDefault();
        blockIp();
    });
}

// Authentication functions
async function handleLogin(e) {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    
    try {
        const response = await fetch(`${API_BASE}/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });
        
        if (response.ok) {
            const data = await response.json();
            authToken = data.token;
            localStorage.setItem('authToken', authToken);
            
            document.getElementById('currentUser').textContent = username;
            hidLogin();
            showDashboard();
            loadOverviewData();
        } else {
            showLoginError('Invalid credentials');
        }
    } catch (error) {
        showLoginError('Connection error');
    }
}

async function validateToken() {
    try {
        const response = await fetch(`${API_BASE}/auth/validate`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (response.ok) {
            showDashboard();
            loadOverviewData();
        } else {
            showLogin();
        }
    } catch (error) {
        showLogin();
    }
}

function logout() {
    authToken = null;
    localStorage.removeItem('authToken');
    showLogin();
}

function showLogin() {
    document.getElementById('dashboard').classList.add('d-none');
    new bootstrap.Modal(document.getElementById('loginModal')).show();
}

function hidLogin() {
    bootstrap.Modal.getInstance(document.getElementById('loginModal')).hide();
}

function showDashboard() {
    document.getElementById('dashboard').classList.remove('d-none');
}

function showLoginError(message) {
    const errorDiv = document.getElementById('loginError');
    errorDiv.textContent = message;
    errorDiv.classList.remove('d-none');
}

// Navigation functions
function showSection(sectionName) {
    // Hide all sections
    document.querySelectorAll('.content-section').forEach(section => {
        section.classList.add('d-none');
    });
    
    // Show selected section
    document.getElementById(`${sectionName}-section`).classList.remove('d-none');
    
    // Update page title
    const titles = {
        'overview': 'System Overview',
        'alerts': 'Security Alerts',
        'blocked-ips': 'Blocked IP Addresses',
        'system': 'System Status'
    };
    document.getElementById('pageTitle').textContent = titles[sectionName] || 'Dashboard';
    
    // Load section data
    switch(sectionName) {
        case 'overview':
            loadOverviewData();
            break;
        case 'alerts':
            loadAlerts();
            break;
        case 'blocked-ips':
            loadBlockedIps();
            break;
        case 'system':
            loadSystemInfo();
            break;
    }
}

// Data loading functions
async function loadOverviewData() {
    try {
        // Load system status
        const statusResponse = await apiCall('/system/status');
        if (statusResponse) {
            updateOverviewStats(statusResponse);
            updateSystemStatus(statusResponse);
        }
        
        // Load recent alerts
        const alertsResponse = await apiCall('/alerts?size=5');
        if (alertsResponse) {
            updateRecentAlerts(alertsResponse);
        }
        
        // Load alert stats
        const alertStatsResponse = await apiCall('/alerts/stats');
        if (alertStatsResponse) {
            document.getElementById('activeAlertsCount').textContent = 
                alertStatsResponse.open_alerts + alertStatsResponse.investigating_alerts;
        }
        
        // Load prevention stats
        const preventionStatsResponse = await apiCall('/block/stats');
        if (preventionStatsResponse) {
            document.getElementById('blockedIpsCount').textContent = preventionStatsResponse.active_blocks;
        }
        
    } catch (error) {
        console.error('Error loading overview data:', error);
    }
}

function updateOverviewStats(data) {
    document.getElementById('packetsAnalyzed').textContent = data.packets_analyzed || '0';
    document.getElementById('systemUptime').textContent = data.uptime || '0h';
}

function updateSystemStatus(data) {
    const statusHtml = `
        <div class="mb-2">
            <span class="status-indicator ${data.sensor_active ? 'status-active' : 'status-inactive'}"></span>
            Network Sensor: ${data.sensor_active ? 'Active' : 'Inactive'}
        </div>
        <div class="mb-2">
            <span class="status-indicator status-active"></span>
            Detection Engine: Active (${data.detection_rules} rules)
        </div>
        <div class="mb-2">
            <span class="status-indicator status-active"></span>
            Prevention System: Active
        </div>
        <div class="mb-2">
            <span class="status-indicator status-active"></span>
            ECC Encryption: Active
        </div>
        <small class="text-muted">Last updated: ${new Date().toLocaleTimeString()}</small>
    `;
    document.getElementById('systemStatus').innerHTML = statusHtml;
}

function updateRecentAlerts(alerts) {
    if (!alerts || alerts.length === 0) {
        document.getElementById('recentAlerts').innerHTML = '<p class="text-muted">No recent alerts</p>';
        return;
    }
    
    const alertsHtml = alerts.map(alert => `
        <div class="alert-card card mb-2 alert-${alert.severity.toLowerCase()}">
            <div class="card-body py-2">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <strong>${alert.alert_type.replace('_', ' ')}</strong>
                        <br>
                        <small>${alert.source_ip} → ${alert.destination_ip}</small>
                    </div>
                    <div class="text-end">
                        <span class="badge bg-${getSeverityColor(alert.severity)}">${alert.severity}</span>
                        <br>
                        <small class="text-muted">${formatTime(alert.timestamp)}</small>
                    </div>
                </div>
            </div>
        </div>
    `).join('');
    
    document.getElementById('recentAlerts').innerHTML = alertsHtml;
}

async function loadAlerts(severity = null) {
    try {
        let url = '/alerts';
        if (severity && severity !== 'all') {
            url += `?severity=${severity}`;
        }
        
        const alerts = await apiCall(url);
        if (alerts) {
            displayAlerts(alerts);
        }
    } catch (error) {
        console.error('Error loading alerts:', error);
        document.getElementById('alertsList').innerHTML = '<div class="alert alert-danger">Error loading alerts</div>';
    }
}

function displayAlerts(alerts) {
    if (!alerts || alerts.length === 0) {
        document.getElementById('alertsList').innerHTML = '<div class="alert alert-info">No alerts found</div>';
        return;
    }
    
    const alertsHtml = alerts.map(alert => `
        <div class="card mb-3 alert-card alert-${alert.severity.toLowerCase()}">
            <div class="card-body">
                <div class="row">
                    <div class="col-md-8">
                        <h6 class="card-title">
                            ${alert.alert_type.replace('_', ' ')}
                            <span class="badge bg-${getSeverityColor(alert.severity)} ms-2">${alert.severity}</span>
                        </h6>
                        <p class="card-text">${alert.description}</p>
                        <small class="text-muted">
                            <i class="fas fa-network-wired me-1"></i>
                            ${alert.source_ip}:${alert.source_port || 'N/A'} → 
                            ${alert.destination_ip}:${alert.destination_port || 'N/A'}
                            ${alert.protocol ? `(${alert.protocol})` : ''}
                        </small>
                    </div>
                    <div class="col-md-4 text-end">
                        <div class="mb-2">
                            <span class="badge bg-secondary">${alert.status}</span>
                        </div>
                        <div class="mb-2">
                            <small class="text-muted">${formatTime(alert.timestamp)}</small>
                        </div>
                        <button class="btn btn-sm btn-outline-primary" onclick="showAlertDetails('${alert.id}')">
                            <i class="fas fa-eye me-1"></i>Details
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `).join('');
    
    document.getElementById('alertsList').innerHTML = alertsHtml;
}

async function loadBlockedIps() {
    try {
        const blockedIps = await apiCall('/block');
        if (blockedIps) {
            displayBlockedIps(blockedIps);
        }
    } catch (error) {
        console.error('Error loading blocked IPs:', error);
        document.getElementById('blockedIpsList').innerHTML = '<div class="alert alert-danger">Error loading blocked IPs</div>';
    }
}

function displayBlockedIps(blockedIps) {
    if (!blockedIps || blockedIps.length === 0) {
        document.getElementById('blockedIpsList').innerHTML = '<div class="alert alert-info">No blocked IPs</div>';
        return;
    }
    
    const ipsHtml = blockedIps.map(ip => `
        <div class="card mb-3">
            <div class="card-body">
                <div class="row align-items-center">
                    <div class="col-md-3">
                        <h6 class="mb-0">${ip.ip}</h6>
                    </div>
                    <div class="col-md-4">
                        <small class="text-muted">${ip.reason}</small>
                    </div>
                    <div class="col-md-3">
                        <small class="text-muted">
                            Blocked: ${formatTime(ip.blocked_at)}<br>
                            ${ip.expires_at ? `Expires: ${formatTime(ip.expires_at)}` : 'Permanent'}
                        </small>
                    </div>
                    <div class="col-md-2 text-end">
                        <button class="btn btn-sm btn-outline-success" onclick="unblockIp('${ip.ip}')">
                            <i class="fas fa-unlock me-1"></i>Unblock
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `).join('');
    
    document.getElementById('blockedIpsList').innerHTML = ipsHtml;
}

async function loadSystemInfo() {
    try {
        const systemInfo = await apiCall('/system/info');
        if (systemInfo) {
            displaySystemInfo(systemInfo);
        }
    } catch (error) {
        console.error('Error loading system info:', error);
    }
}

function displaySystemInfo(info) {
    const infoHtml = `
        <div class="row">
            <div class="col-md-6">
                <h6>Application Information</h6>
                <table class="table table-sm">
                    <tr><td>Name:</td><td>${info.application_name}</td></tr>
                    <tr><td>Version:</td><td>${info.version}</td></tr>
                    <tr><td>Build Time:</td><td>${formatTime(info.build_time)}</td></tr>
                </table>
                
                <h6 class="mt-4">System Information</h6>
                <table class="table table-sm">
                    <tr><td>Java Version:</td><td>${info.java_version}</td></tr>
                    <tr><td>OS:</td><td>${info.os_name} ${info.os_version}</td></tr>
                    <tr><td>Processors:</td><td>${info.jvm_processors}</td></tr>
                </table>
            </div>
            <div class="col-md-6">
                <h6>Memory Usage</h6>
                <table class="table table-sm">
                    <tr><td>Total:</td><td>${formatBytes(info.jvm_memory_total)}</td></tr>
                    <tr><td>Used:</td><td>${formatBytes(info.jvm_memory_used)}</td></tr>
                    <tr><td>Free:</td><td>${formatBytes(info.jvm_memory_free)}</td></tr>
                </table>
                
                <h6 class="mt-4">Component Status</h6>
                <table class="table table-sm">
                    <tr><td>Sensor:</td><td><span class="badge bg-success">${info.components.sensor.status}</span></td></tr>
                    <tr><td>Detection:</td><td><span class="badge bg-success">${info.components.detection.status}</span></td></tr>
                    <tr><td>Prevention:</td><td><span class="badge bg-success">${info.components.prevention.status}</span></td></tr>
                    <tr><td>Encryption:</td><td><span class="badge bg-success">${info.components.encryption.status}</span></td></tr>
                </table>
            </div>
        </div>
    `;
    
    document.getElementById('detailedSystemInfo').innerHTML = infoHtml;
}

// Utility functions
async function apiCall(endpoint, options = {}) {
    const defaultOptions = {
        headers: {
            'Authorization': `Bearer ${authToken}`,
            'Content-Type': 'application/json'
        }
    };
    
    const response = await fetch(`${API_BASE}${endpoint}`, { ...defaultOptions, ...options });
    
    if (response.status === 401) {
        logout();
        return null;
    }
    
    if (!response.ok) {
        throw new Error(`API call failed: ${response.status}`);
    }
    
    return await response.json();
}

function getSeverityColor(severity) {
    const colors = {
        'CRITICAL': 'danger',
        'HIGH': 'warning',
        'MEDIUM': 'info',
        'LOW': 'success'
    };
    return colors[severity] || 'secondary';
}

function formatTime(timestamp) {
    return new Date(timestamp).toLocaleString();
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function refreshData() {
    const activeSection = document.querySelector('.nav-link.active').dataset.section;
    showSection(activeSection);
}

// Alert functions
function filterAlerts(severity) {
    // Update active filter button
    document.querySelectorAll('.btn-group .btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
    
    loadAlerts(severity);
}

async function showAlertDetails(alertId) {
    try {
        const alert = await apiCall(`/alerts/${alertId}`);
        if (alert) {
            currentAlert = alert;
            displayAlertDetails(alert);
            new bootstrap.Modal(document.getElementById('alertDetailsModal')).show();
        }
    } catch (error) {
        console.error('Error loading alert details:', error);
    }
}

function displayAlertDetails(alert) {
    const detailsHtml = `
        <div class="row">
            <div class="col-md-6">
                <h6>Alert Information</h6>
                <table class="table table-sm">
                    <tr><td>ID:</td><td>${alert.id}</td></tr>
                    <tr><td>Type:</td><td>${alert.alert_type.replace('_', ' ')}</td></tr>
                    <tr><td>Severity:</td><td><span class="badge bg-${getSeverityColor(alert.severity)}">${alert.severity}</span></td></tr>
                    <tr><td>Status:</td><td>${alert.status}</td></tr>
                    <tr><td>Timestamp:</td><td>${formatTime(alert.timestamp)}</td></tr>
                </table>
            </div>
            <div class="col-md-6">
                <h6>Network Information</h6>
                <table class="table table-sm">
                    <tr><td>Source IP:</td><td>${alert.source_ip}</td></tr>
                    <tr><td>Source Port:</td><td>${alert.source_port || 'N/A'}</td></tr>
                    <tr><td>Destination IP:</td><td>${alert.destination_ip}</td></tr>
                    <tr><td>Destination Port:</td><td>${alert.destination_port || 'N/A'}</td></tr>
                    <tr><td>Protocol:</td><td>${alert.protocol || 'N/A'}</td></tr>
                </table>
            </div>
        </div>
        <div class="row mt-3">
            <div class="col-12">
                <h6>Description</h6>
                <p>${alert.description}</p>
                <div id="decryptedDetails" class="d-none">
                    <h6>Decrypted Details</h6>
                    <pre id="decryptedContent" class="bg-light p-3"></pre>
                </div>
            </div>
        </div>
    `;
    
    document.getElementById('alertDetailsContent').innerHTML = detailsHtml;
}

async function decryptAlert() {
    if (!currentAlert || !currentAlert.alert_encrypted) {
        alert('No encrypted data available');
        return;
    }
    
    try {
        const response = await apiCall('/alerts/decrypt', {
            method: 'POST',
            body: JSON.stringify({
                encrypted_alert: currentAlert.alert_encrypted
            })
        });
        
        if (response) {
            document.getElementById('decryptedContent').textContent = response.alert_text;
            document.getElementById('decryptedDetails').classList.remove('d-none');
        }
    } catch (error) {
        console.error('Error decrypting alert:', error);
        alert('Failed to decrypt alert details');
    }
}

// IP blocking functions
async function blockIp() {
    const ip = document.getElementById('ipAddress').value;
    const reason = document.getElementById('blockReason').value;
    
    if (!ip || !reason) {
        alert('Please fill in all fields');
        return;
    }
    
    try {
        const response = await apiCall('/block', {
            method: 'POST',
            body: JSON.stringify({ ip, reason })
        });
        
        if (response) {
            bootstrap.Modal.getInstance(document.getElementById('blockIpModal')).hide();
            document.getElementById('blockIpForm').reset();
            loadBlockedIps();
            alert('IP blocked successfully');
        }
    } catch (error) {
        console.error('Error blocking IP:', error);
        alert('Failed to block IP');
    }
}

async function unblockIp(ip) {
    if (!confirm(`Are you sure you want to unblock ${ip}?`)) {
        return;
    }
    
    try {
        const response = await apiCall(`/block/${ip}`, {
            method: 'DELETE'
        });
        
        if (response) {
            loadBlockedIps();
            alert('IP unblocked successfully');
        }
    } catch (error) {
        console.error('Error unblocking IP:', error);
        alert('Failed to unblock IP');
    }
}
