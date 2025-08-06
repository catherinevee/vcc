/**
 * VCC - Vibe-Code Checker Frontend Application
 * Author: Aziza Ocosso
 * Company: VCCC
 * 
 * Core frontend logic without decorative animations or AI patterns
 * Focus on functionality, security, and performance
 */

(function() {
    'use strict';

    // ============================================
    // APPLICATION STATE
    // ============================================
    
    const VCC = {
        // Configuration
        config: {
            apiBase: window.location.origin + '/api',
            wsUrl: window.location.origin,
            maxRetries: 3,
            retryDelay: 1000,
            analysisTimeout: 180000, // 3 minutes
            debounceDelay: 300
        },
        
        // Application state
        state: {
            user: null,
            currentAnalysis: null,
            socket: null,
            repositories: [],
            analysisHistory: [],
            dailyLimit: 20,
            remainingAnalyses: 20,
            csrfToken: null
        },
        
        // DOM element cache
        elements: {},
        
        // Active timers
        timers: {}
    };

    // ============================================
    // INITIALIZATION
    // ============================================
    
    /**
     * Initialize the VCC application
     */
    VCC.init = function() {
        // Cache DOM elements
        this.cacheElements();
        
        // Get CSRF token
        this.state.csrfToken = this.getCSRFToken();
        
        // Setup event listeners
        this.bindEvents();
        
        // Initialize WebSocket if on dashboard
        if (window.location.pathname === '/dashboard') {
            this.initWebSocket();
            this.loadDashboard();
        }
        
        // Check authentication status
        this.checkAuth();
        
        // Setup error handlers
        this.setupErrorHandlers();
    };

    /**
     * Cache commonly used DOM elements
     */
    VCC.cacheElements = function() {
        this.elements = {
            // Navigation
            loginBtn: document.getElementById('loginBtn'),
            logoutBtn: document.getElementById('logoutBtn'),
            userInfo: document.getElementById('userInfo'),
            userName: document.getElementById('userName'),
            
            // Dashboard
            repoList: document.getElementById('repoList'),
            historyList: document.getElementById('historyList'),
            totalRepos: document.getElementById('totalRepos'),
            analyzedToday: document.getElementById('analyzedToday'),
            criticalFound: document.getElementById('criticalFound'),
            remainingScans: document.getElementById('remainingScans'),
            
            // Modal
            analysisModal: document.getElementById('analysisModal'),
            modalClose: document.getElementById('modalClose'),
            modalRepoName: document.getElementById('modalRepoName'),
            analysisState: document.getElementById('analysisState'),
            analysisStep: document.getElementById('analysisStep'),
            resultsState: document.getElementById('resultsState'),
            
            // Results
            scoreValue: document.getElementById('scoreValue'),
            findingsList: document.getElementById('findingsList'),
            
            // Actions
            exportJsonBtn: document.getElementById('exportJsonBtn'),
            exportMarkdownBtn: document.getElementById('exportMarkdownBtn')
        };
    };

    /**
     * Bind event listeners
     */
    VCC.bindEvents = function() {
        // Modal close
        if (this.elements.modalClose) {
            this.elements.modalClose.addEventListener('click', () => this.closeModal());
        }
        
        // Export buttons
        if (this.elements.exportJsonBtn) {
            this.elements.exportJsonBtn.addEventListener('click', () => this.exportResults('json'));
        }
        
        if (this.elements.exportMarkdownBtn) {
            this.elements.exportMarkdownBtn.addEventListener('click', () => this.exportResults('markdown'));
        }
        
        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => this.handleKeyPress(e));
        
        // Repository clicks (delegated)
        if (this.elements.repoList) {
            this.elements.repoList.addEventListener('click', (e) => {
                const repoItem = e.target.closest('.vcc-repo-item');
                if (repoItem) {
                    const repoData = JSON.parse(repoItem.dataset.repo);
                    this.analyzeRepository(repoData);
                }
            });
        }
        
        // Window events
        window.addEventListener('beforeunload', () => this.cleanup());
    };

    // ============================================
    // AUTHENTICATION
    // ============================================
    
    /**
     * Check authentication status
     */
    VCC.checkAuth = async function() {
        try {
            const response = await this.apiRequest('/user');
            if (response.ok) {
                const userData = await response.json();
                this.state.user = userData;
                this.updateUserInterface(userData);
            }
        } catch (error) {
            console.error('Auth check failed:', error);
        }
    };

    /**
     * Update UI with user information
     */
    VCC.updateUserInterface = function(user) {
        if (this.elements.userName) {
            this.elements.userName.textContent = user.name || user.login;
        }
        
        if (this.elements.userInfo) {
            this.elements.userInfo.style.display = 'flex';
        }
    };

    // ============================================
    // DASHBOARD
    // ============================================
    
    /**
     * Load dashboard data
     */
    VCC.loadDashboard = async function() {
        try {
            // Load user data from session or API
            const response = await this.apiRequest('/dashboard/data');
            const data = await response.json();
            
            this.state.repositories = data.repositories;
            this.state.analysisHistory = data.history;
            this.state.remainingAnalyses = data.remaining;
            
            this.renderRepositories();
            this.renderHistory();
            this.updateStats();
            
        } catch (error) {
            console.error('Dashboard load failed:', error);
            this.showError('Failed to load dashboard data');
        }
    };

    /**
     * Render repository list
     */
    VCC.renderRepositories = function() {
        if (!this.elements.repoList) return;
        
        const fragment = document.createDocumentFragment();
        
        this.state.repositories.forEach(repo => {
            const li = document.createElement('li');
            li.className = 'vcc-repo-item';
            li.dataset.repo = JSON.stringify(repo);
            
            // Build repo item HTML safely
            const header = document.createElement('div');
            header.className = 'vcc-repo-header';
            
            const name = document.createElement('span');
            name.className = 'vcc-repo-name';
            name.textContent = repo.name;
            
            const language = document.createElement('span');
            language.className = 'vcc-repo-language';
            language.textContent = repo.language || 'Unknown';
            
            header.appendChild(name);
            header.appendChild(language);
            
            // Description
            if (repo.description) {
                const desc = document.createElement('div');
                desc.className = 'vcc-repo-desc';
                desc.textContent = repo.description;
                li.appendChild(desc);
            }
            
            // Meta information
            const meta = document.createElement('div');
            meta.className = 'vcc-repo-meta';
            
            const stars = document.createElement('span');
            stars.textContent = `Stars: ${repo.stargazers_count}`;
            
            const forks = document.createElement('span');
            forks.textContent = `Forks: ${repo.forks_count}`;
            
            const size = document.createElement('span');
            size.textContent = `Size: ${(repo.size / 1024).toFixed(1)}MB`;
            
            meta.appendChild(stars);
            meta.appendChild(forks);
            meta.appendChild(size);
            
            li.appendChild(header);
            li.appendChild(meta);
            
            fragment.appendChild(li);
        });
        
        this.elements.repoList.innerHTML = '';
        this.elements.repoList.appendChild(fragment);
        
        // Update count
        if (this.elements.totalRepos) {
            this.elements.totalRepos.textContent = this.state.repositories.length;
        }
    };

    /**
     * Render analysis history
     */
    VCC.renderHistory = function() {
        if (!this.elements.historyList) return;
        
        if (this.state.analysisHistory.length === 0) {
            this.elements.historyList.innerHTML = `
                <div class="vcc-empty-state">
                    <div class="vcc-empty-title">No analyses yet</div>
                    <div class="vcc-empty-desc">Select a repository above to start analyzing</div>
                </div>
            `;
            return;
        }
        
        const fragment = document.createDocumentFragment();
        
        this.state.analysisHistory.forEach(item => {
            const div = document.createElement('div');
            div.className = 'vcc-history-item';
            
            const info = document.createElement('div');
            
            const repo = document.createElement('div');
            repo.className = 'vcc-history-repo';
            repo.textContent = item.repository;
            
            const date = document.createElement('div');
            date.className = 'vcc-history-date';
            date.textContent = new Date(item.timestamp).toLocaleString();
            
            info.appendChild(repo);
            info.appendChild(date);
            
            const score = document.createElement('div');
            score.className = 'vcc-history-score';
            score.textContent = item.score;
            
            // Add severity class
            if (item.score >= 80) score.classList.add('critical');
            else if (item.score >= 50) score.classList.add('high');
            else if (item.score >= 30) score.classList.add('medium');
            else score.classList.add('low');
            
            div.appendChild(info);
            div.appendChild(score);
            
            fragment.appendChild(div);
        });
        
        this.elements.historyList.innerHTML = '';
        this.elements.historyList.appendChild(fragment);
    };

    /**
     * Update dashboard statistics
     */
    VCC.updateStats = function() {
        if (this.elements.analyzedToday) {
            const today = this.state.analysisHistory.filter(item => {
                const date = new Date(item.timestamp);
                const now = new Date();
                return date.toDateString() === now.toDateString();
            });
            this.elements.analyzedToday.textContent = today.length;
        }
        
        if (this.elements.criticalFound) {
            const critical = this.state.analysisHistory.reduce((sum, item) => {
                return sum + (item.critical_vulnerabilities || 0);
            }, 0);
            this.elements.criticalFound.textContent = critical;
        }
        
        if (this.elements.remainingScans) {
            this.elements.remainingScans.textContent = this.state.remainingAnalyses;
        }
    };

    // ============================================
    // ANALYSIS
    // ============================================
    
    /**
     * Start repository analysis
     */
    VCC.analyzeRepository = async function(repo) {
        // Check remaining analyses
        if (this.state.remainingAnalyses <= 0) {
            this.showError('Daily analysis limit reached. Upgrade to VCC Pro for unlimited analyses.');
            return;
        }
        
        this.state.currentAnalysis = repo;
        
        // Show modal
        this.showModal();
        this.showAnalysisState();
        
        if (this.elements.modalRepoName) {
            this.elements.modalRepoName.textContent = repo.name;
        }
        
        try {
            const response = await this.apiRequest('/analyze', {
                method: 'POST',
                body: JSON.stringify({ 
                    repo_url: repo.clone_url,
                    repo_name: repo.name
                })
            });
            
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.message || 'Analysis failed');
            }
            
            const data = await response.json();
            
            // Join WebSocket room for updates
            if (this.state.socket) {
                this.state.socket.emit('join_analysis', { 
                    room_id: data.room_id 
                });
            }
            
            // Set timeout for analysis
            this.timers.analysisTimeout = setTimeout(() => {
                this.showError('Analysis timeout. Please try again.');
                this.closeModal();
            }, this.config.analysisTimeout);
            
        } catch (error) {
            console.error('Analysis failed:', error);
            this.showError(error.message);
            this.closeModal();
        }
    };

    /**
     * Handle analysis progress updates
     */
    VCC.handleAnalysisProgress = function(data) {
        if (this.elements.analysisStep) {
            const steps = {
                10: 'Cloning repository',
                30: 'Scanning for vulnerabilities',
                50: 'Analyzing architecture',
                70: 'Checking performance patterns',
                90: 'Generating report',
                100: 'Analysis complete'
            };
            
            this.elements.analysisStep.textContent = steps[data.progress] || data.message;
        }
    };

    /**
     * Handle analysis completion
     */
    VCC.handleAnalysisComplete = function(data) {
        // Clear timeout
        if (this.timers.analysisTimeout) {
            clearTimeout(this.timers.analysisTimeout);
            delete this.timers.analysisTimeout;
        }
        
        // Display results
        this.displayResults(data.report);
        
        // Update history
        this.addToHistory({
            repository: this.state.currentAnalysis.name,
            score: data.report.vibe_coding_score,
            critical_vulnerabilities: data.report.critical_vulnerabilities,
            timestamp: new Date().toISOString()
        });
        
        // Update remaining count
        this.state.remainingAnalyses--;
        this.updateStats();
    };

    /**
     * Display analysis results
     */
    VCC.displayResults = function(report) {
        this.showResultsState();
        
        // Display score
        if (this.elements.scoreValue) {
            this.elements.scoreValue.textContent = report.vibe_coding_score;
            
            // Set severity class
            this.elements.scoreValue.className = 'vcc-score';
            if (report.vibe_coding_score >= 80) {
                this.elements.scoreValue.classList.add('critical');
            } else if (report.vibe_coding_score >= 50) {
                this.elements.scoreValue.classList.add('high');
            } else if (report.vibe_coding_score >= 30) {
                this.elements.scoreValue.classList.add('medium');
            } else {
                this.elements.scoreValue.classList.add('low');
            }
        }
        
        // Display findings
        if (this.elements.findingsList) {
            this.renderFindings(report.findings);
        }
        
        // Store report for export
        this.state.currentReport = report;
    };

    /**
     * Render findings list
     */
    VCC.renderFindings = function(findings) {
        const fragment = document.createDocumentFragment();
        
        // Limit to top 10 findings
        findings.slice(0, 10).forEach(finding => {
            const div = document.createElement('div');
            div.className = `vcc-finding ${finding.severity.toLowerCase()}`;
            
            const header = document.createElement('div');
            header.className = 'vcc-finding-header';
            
            const title = document.createElement('span');
            title.className = 'vcc-finding-title';
            title.textContent = finding.description;
            
            const severity = document.createElement('span');
            severity.className = 'vcc-finding-severity';
            severity.textContent = finding.severity;
            
            header.appendChild(title);
            header.appendChild(severity);
            
            const location = document.createElement('div');
            location.className = 'vcc-finding-location';
            location.textContent = `${finding.file_path}:${finding.line_number}`;
            
            const fix = document.createElement('div');
            fix.className = 'vcc-finding-fix';
            fix.textContent = `Fix: ${finding.fix_suggestion}`;
            
            div.appendChild(header);
            div.appendChild(location);
            div.appendChild(fix);
            
            fragment.appendChild(div);
        });
        
        this.elements.findingsList.innerHTML = '';
        this.elements.findingsList.appendChild(fragment);
    };

    /**
     * Add analysis to history
     */
    VCC.addToHistory = function(analysis) {
        this.state.analysisHistory.unshift(analysis);
        
        // Keep only last 20 items
        if (this.state.analysisHistory.length > 20) {
            this.state.analysisHistory = this.state.analysisHistory.slice(0, 20);
        }
        
        this.renderHistory();
    };

    // ============================================
    // WEBSOCKET
    // ============================================
    
    /**
     * Initialize WebSocket connection
     */
    VCC.initWebSocket = function() {
        if (typeof io === 'undefined') {
            console.error('Socket.IO not loaded');
            return;
        }
        
        this.state.socket = io(this.config.wsUrl, {
            transports: ['websocket'],
            reconnection: true,
            reconnectionDelay: 1000,
            reconnectionAttempts: 5
        });
        
        // Socket event handlers
        this.state.socket.on('connect', () => {
            console.log('WebSocket connected');
        });
        
        this.state.socket.on('analysis_progress', (data) => {
            this.handleAnalysisProgress(data);
        });
        
        this.state.socket.on('analysis_complete', (data) => {
            this.handleAnalysisComplete(data);
        });
        
        this.state.socket.on('analysis_error', (data) => {
            this.showError(data.message);
            this.closeModal();
        });
        
        this.state.socket.on('disconnect', () => {
            console.log('WebSocket disconnected');
        });
    };

    // ============================================
    // MODAL CONTROL
    // ============================================
    
    /**
     * Show modal
     */
    VCC.showModal = function() {
        if (this.elements.analysisModal) {
            this.elements.analysisModal.classList.add('active');
        }
    };

    /**
     * Close modal
     */
    VCC.closeModal = function() {
        if (this.elements.analysisModal) {
            this.elements.analysisModal.classList.remove('active');
        }
        
        // Leave analysis room if connected
        if (this.state.socket && this.state.currentAnalysis) {
            this.state.socket.emit('leave_analysis', { 
                room_id: this.state.currentAnalysis.room_id 
            });
        }
        
        this.state.currentAnalysis = null;
    };

    /**
     * Show analysis state
     */
    VCC.showAnalysisState = function() {
        if (this.elements.analysisState) {
            this.elements.analysisState.style.display = 'block';
        }
        if (this.elements.resultsState) {
            this.elements.resultsState.classList.remove('active');
        }
    };

    /**
     * Show results state
     */
    VCC.showResultsState = function() {
        if (this.elements.analysisState) {
            this.elements.analysisState.style.display = 'none';
        }
        if (this.elements.resultsState) {
            this.elements.resultsState.classList.add('active');
        }
    };

    // ============================================
    // EXPORT
    // ============================================
    
    /**
     * Export analysis results
     */
    VCC.exportResults = async function(format) {
        if (!this.state.currentReport) {
            this.showError('No results to export');
            return;
        }
        
        try {
            const response = await this.apiRequest(`/export?format=${format}`, {
                method: 'POST',
                body: JSON.stringify(this.state.currentReport)
            });
            
            if (!response.ok) {
                throw new Error('Export failed');
            }
            
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `vcc-analysis-${Date.now()}.${format}`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
            
        } catch (error) {
            console.error('Export failed:', error);
            this.showError('Failed to export results');
        }
    };

    // ============================================
    // UTILITIES
    // ============================================
    
    /**
     * Make API request with CSRF token
     */
    VCC.apiRequest = function(endpoint, options = {}) {
        const url = endpoint.startsWith('http') ? endpoint : this.config.apiBase + endpoint;
        
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };
        
        if (this.state.csrfToken) {
            headers['X-CSRF-Token'] = this.state.csrfToken;
        }
        
        return fetch(url, {
            ...options,
            headers,
            credentials: 'same-origin'
        });
    };

    /**
     * Get CSRF token from meta tag
     */
    VCC.getCSRFToken = function() {
        const meta = document.querySelector('meta[name="csrf-token"]');
        return meta ? meta.getAttribute('content') : null;
    };

    /**
     * Show error message
     */
    VCC.showError = function(message) {
        // Simple console error for now
        // In production, this would show a user-friendly error
        console.error('VCC Error:', message);
        
        // Update UI if in analysis mode
        if (this.elements.analysisStep) {
            this.elements.analysisStep.textContent = `Error: ${message}`;
            this.elements.analysisStep.style.color = 'var(--vcc-critical)';
        }
    };

    /**
     * Handle keyboard shortcuts
     */
    VCC.handleKeyPress = function(e) {
        // Escape to close modal
        if (e.key === 'Escape') {
            this.closeModal();
        }
        
        // Ctrl+E to export
        if (e.ctrlKey && e.key === 'e') {
            e.preventDefault();
            this.exportResults('json');
        }
    };

    /**
     * Setup global error handlers
     */
    VCC.setupErrorHandlers = function() {
        window.addEventListener('error', (e) => {
            console.error('Global error:', e.error);
        });
        
        window.addEventListener('unhandledrejection', (e) => {
            console.error('Unhandled promise rejection:', e.reason);
        });
    };

    /**
     * Cleanup on page unload
     */
    VCC.cleanup = function() {
        // Close WebSocket
        if (this.state.socket) {
            this.state.socket.disconnect();
        }
        
        // Clear timers
        Object.values(this.timers).forEach(timer => clearTimeout(timer));
    };

    // ============================================
    // INITIALIZATION
    // ============================================
    
    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => VCC.init());
    } else {
        VCC.init();
    }
    
    // Export VCC to global scope for debugging
    window.VCC = VCC;

})();