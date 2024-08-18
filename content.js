// Configuration
const legitimateDomains = ['paypal.com', 'example.com', 'yourlegitdomain.com']; // Trusted domains
const suspiciousTLDs = ['.xyz', '.info', '.top', '.club', '.site', '.space'];
const suspiciousPatterns = [
    /\blogin\./i,
    /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/,
    /@/,
    /%[0-9A-Fa-f]{2}/,
    /[\-\_]{2,}/
];

// Levenshtein distance function for fuzzy domain matching
function levenshtein(a, b) {
    const tmp = [];
    for (let i = 0; i <= b.length; i++) {
        tmp[i] = i;
    }
    for (let i = 0; i < a.length; i++) {
        let prev = i + 1;
        for (let j = 0; j < b.length; j++) {
            const val = a[i] === b[j] ? tmp[j] : Math.min(tmp[j] + 1, prev + 1, tmp[j + 1] + 1);
            tmp[j] = prev;
            prev = val;
        }
        tmp[b.length] = prev;
    }
    return tmp[b.length];
}

// Function to validate and sanitize URL
function sanitizeURL(url) {
    try {
        const cleanUrl = url.trim().replace(/[\s<>]/g, '');
        if (cleanUrl.startsWith('http://') || cleanUrl.startsWith('https://')) {
            return new URL(cleanUrl);
        } else {
            return new URL(`http://${cleanUrl}`);
        }
    } catch {
        return null;
    }
}

// Function to normalize URLs
function normalizeURL(url) {
    const urlObj = sanitizeURL(url);
    return urlObj ? `${urlObj.origin}${urlObj.pathname.toLowerCase()}` : url.toLowerCase();
}

// Function to check if a domain is legitimate using fuzzy matching and typosquatting detection
function isLegitimateDomain(url) {
    const sanitizedUrl = sanitizeURL(url);
    if (!sanitizedUrl) return false;
    const hostname = sanitizedUrl.hostname.toLowerCase();

    // Check for exact match or very close match (e.g., paypa1.com vs paypal.com)
    return legitimateDomains.some(domain => {
        return hostname === domain || hostname.endsWith(`.${domain}`) || levenshtein(hostname, domain) <= 2;
    });
}

// Function to check the domain against reputation services (placeholder function)
async function checkDomainReputation(url) {
    // Integrate with a service like Google Safe Browsing, VirusTotal, etc.
    // Placeholder logic: Assume reputation check passes if the domain is legitimate
    return isLegitimateDomain(url) ? 'safe' : 'unknown';
}

// Function to expand shortened URLs (if needed)
async function expandShortenedURL(url) {
    // Implement logic to expand URLs shortened by services like bit.ly
    // Placeholder logic: Assume the URL is not shortened
    return url;
}

// Function to get reasons for suspicious URLs
async function getSuspiciousReason(url) {
    const sanitizedUrl = sanitizeURL(url);
    if (!sanitizedUrl) return 'Invalid URL.';

    const normalizedURL = await expandShortenedURL(normalizeURL(url));
    const hostname = sanitizedUrl.hostname.toLowerCase();
    const reasons = [];

    const reputation = await checkDomainReputation(url);
    if (reputation !== 'safe') {
        reasons.push('Domain is not on the trusted list or has a poor reputation.');
    }

    if (suspiciousTLDs.some(tld => hostname.endsWith(tld))) {
        reasons.push('Uses suspicious top-level domain (TLD).');
    }

    if (suspiciousPatterns.some(pattern => pattern.test(normalizedURL))) {
        reasons.push('Matches known suspicious patterns.');
    }

    if (!isLegitimateDomain(url)) {
        reasons.push('Potential typosquatting detected: Domain resembles a trusted domain.');
    }

    return reasons.length > 0 ? reasons.join(' ') : null;
}

// Function to highlight or modify elements based on suspicion level
function modifyElement(element, message, alertLevel) {
    element.style.position = 'relative';

    if (alertLevel === 'high') {
        element.style.color = 'red';  // High alert: Change text color to red
        element.addEventListener('mouseenter', event => showPopup(event, message, element.href));
        element.addEventListener('mouseleave', hidePopup);
    } else if (alertLevel === 'medium') {
        element.style.color = 'yellow';  // Medium alert: Change text color to yellow
    }
}

// Add CSS for popups
const style = document.createElement('style');
style.textContent = `
    .popup {
        position: absolute;
        padding: 10px;
        background-color: black;
        border: 2px solid white;
        z-index: 1000;
        max-width: 300px;
        box-shadow: 0 0 5px black;
        border-radius: 5px;
        font-size: 12px;
        color: white;
        font-family: Arial, sans-serif;
        opacity: 0;
        transition: opacity 0.3s ease-in-out;
    }
    .popup.show {
        opacity: 1;
    }
    .popup.alert {
        border-color: red;
    }
    .popup .header {
        font-weight: bold;
        margin-bottom: 5px;
    }
`;
document.head.appendChild(style);

// Function to show popup on hover
function showPopup(event, message, url) {
    const popup = document.createElement('div');
    popup.className = 'popup';

    getSuspiciousReason(url).then(reason => {
        popup.classList.toggle('alert', reason && !url.startsWith('http:'));
        popup.innerHTML = `
            <div class="header">${reason ? 'Alert: Suspicious URL' : 'Info'}</div>
            <div>${message}</div>
            <div>Destination: ${url}</div>
            <div>Reason: ${reason || 'Unknown'}</div>
        `;

        document.body.appendChild(popup);
        popup.classList.add('show');

        popup.style.left = `${event.pageX + 10}px`;
        popup.style.top = `${event.pageY + 10}px`;
    });
}

// Function to hide popup
function hidePopup() {
    document.querySelectorAll('.popup').forEach(popup => {
        popup.classList.remove('show');
        setTimeout(() => popup.remove(), 300);
    });
}

// Function to check URLs on the page and apply different security measures
function scanPage() {
    document.querySelectorAll('a').forEach(async (link) => {
        const reason = await getSuspiciousReason(link.href);
        if (reason) {
            modifyElement(link, reason, 'high');  // High alert for suspicious links (red text)
        } else if (link.href.startsWith('http:')) {
            modifyElement(link, 'This link uses an insecure protocol (HTTP).', 'medium');  // Medium alert for HTTP links (yellow text)
        }
    });
}

// Run checks on initial load
scanPage();

// Observe DOM changes and re-run checks if needed
const observer = new MutationObserver(scanPage);
observer.observe(document.body, { childList: true, subtree: true });
