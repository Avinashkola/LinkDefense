// Load the Top 1 Million Domains into a Set using Fetch API
async function loadLegitimateDomains(csvFilePath) {
    const legitimateDomains = new Set();

    try {
        const response = await fetch(csvFilePath);
        const data = await response.text();

        data.split('\n').forEach((line) => {
            const domain = line.split(',')[1]?.trim().toLowerCase(); // Extract domain from CSV
            if (domain) {
                legitimateDomains.add(domain);
            }
        });

        return legitimateDomains;
    } catch (error) {
        console.error('Error loading legitimate domains:', error);
        return legitimateDomains;
    }
}

// Utility Functions
const utils = {
    // Whitelist of well-known legitimate domains
    whitelist: new Set([
        'gmail.com',
        'google.com',
        'github.com',
        'paypal.com',
        'amazon.com',
        // Add more domains as needed
    ]),

    sanitizeURL: function (url) {
        try {
            const cleanUrl = url.trim().replace(/[\s<>]/g, '');
            return new URL(cleanUrl.startsWith('http') ? cleanUrl : `http://${cleanUrl}`);
        } catch (error) {
            console.error('Invalid URL:', url);
            return null;
        }
    },

    isSuspicious: function (hostname, legitimateDomains) {
        const suspiciousTLDs = ['xyz', 'top', 'loan', 'work']; // Add more as needed
        const suspiciousPatterns = [
            /[^a-zA-Z0-9.-]/g,  // Unusual symbols in domain names
            /^\d+$/g,  // Domains that are entirely numbers
            /%[0-9A-Fa-f]{2}/,  // URL-encoded characters
        ];

        // If the domain is whitelisted, it's considered safe
        if (this.whitelist.has(hostname)) {
            return false;
        }

        // Check if the domain is in the legitimate domains list
        if (legitimateDomains.has(hostname)) {
            return false;
        }

        // Check for suspicious TLDs
        const tld = hostname.split('.').pop();
        if (suspiciousTLDs.includes(tld)) {
            return true;
        }

        // Check for suspicious patterns
        if (suspiciousPatterns.some(pattern => pattern.test(hostname))) {
            return true;
        }

        // Check for typosquatting using Levenshtein distance
        if (this.isTyposquatting(hostname, legitimateDomains)) {
            return true;
        }

        return false;
    },

    isTyposquatting: function (hostname, legitimateDomains) {
        const baseDomain = hostname.split('.').slice(-2).join('.');

        // Implementing a simple Levenshtein distance check for typosquatting detection
        const levenshteinDistance = (a, b) => {
            const matrix = Array.from({ length: b.length + 1 }, (_, i) => [i]);
            for (let i = 0; i <= a.length; i++) matrix[0][i] = i;
            for (let i = 1; i <= b.length; i++) {
                for (let j = 1; j <= a.length; j++) {
                    matrix[i][j] = b[i - 1] === a[j - 1] ? matrix[i - 1][j - 1] :
                        Math.min(matrix[i - 1][j - 1] + 1, matrix[i][j - 1] + 1, matrix[i - 1][j] + 1);
                }
            }
            return matrix[b.length][a.length];
        };

        for (const legitimateDomain of legitimateDomains) {
            if (levenshteinDistance(baseDomain, legitimateDomain) <= 1) {
                return true;
            }
        }

        return false;
    },

    isIPAddress: function (hostname) {
        return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
    },

    isHTTP: function (url) {
        return url.protocol === 'http:';
    }
};

// Main URL Checking Functionality
const urlChecker = {
    markAsSuspicious: function (element) {
        console.log(`Marking link as suspicious: ${element.href || element.action}`);
        element.style.color = 'red';  // Change the text color to red
    },

    async scanPage(legitimateDomains) {
        const links = document.querySelectorAll('a[href], form[action]');
        for (let element of links) {
            const url = element.href || element.action;
            if (!url) continue;

            const sanitizedUrl = utils.sanitizeURL(url);
            if (!sanitizedUrl) continue;

            const hostname = sanitizedUrl.hostname.toLowerCase();

            // Check for HTTP protocol
            if (utils.isHTTP(sanitizedUrl)) {
                this.markAsSuspicious(element);
                continue;
            }

            // Check for IP addresses in URL
            if (utils.isIPAddress(hostname)) {
                this.markAsSuspicious(element);
                continue;
            }

            // Check for suspicious or typosquatting domain names
            if (utils.isSuspicious(hostname, legitimateDomains)) {
                this.markAsSuspicious(element);
                continue;
            }

            // Check for shortened URLs
            if (/^http:\/\/(bit\.ly|t\.co|tinyurl\.com|goo\.gl)/.test(hostname)) {
                this.markAsSuspicious(element);
                continue;
            }
        }
    },

    observeDOMChanges: function (legitimateDomains) {
        const observer = new MutationObserver(() => this.scanPage(legitimateDomains));
        observer.observe(document.body, { childList: true, subtree: true });
    }
};

// Initialize Scanning
(async function () {
    const legitimateDomains = await loadLegitimateDomains(chrome.runtime.getURL('top-1m.csv'));
    await urlChecker.scanPage(legitimateDomains);
    urlChecker.observeDOMChanges(legitimateDomains);
})();
