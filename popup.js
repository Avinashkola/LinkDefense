document.addEventListener('DOMContentLoaded', function () {
    // Request suspicious URLs from the background script
    chrome.runtime.sendMessage({ action: 'getSuspiciousURLs' }, (response) => {
        let urlList = document.getElementById('urlList');
        let status = document.getElementById('status');

        if (response.urls.length > 0) {
            status.textContent = 'Suspicious URLs found:';
            response.urls.forEach((url) => {
                let listItem = document.createElement('li');
                listItem.textContent = url;
                urlList.appendChild(listItem);
            });
        } else {
            status.textContent = 'No suspicious URLs found.';
        }
    });

    // Request redirected URLs from the background script
    chrome.runtime.sendMessage({ action: 'getRedirectedURLs' }, (response) => {
        let redirectList = document.getElementById('redirectList');

        if (response.urls.length > 0) {
            response.urls.forEach((url) => {
                let listItem = document.createElement('li');
                listItem.textContent = url;
                redirectList.appendChild(listItem);
            });
        } else {
            redirectList.innerHTML = '<li>No redirections found.</li>';
        }
    });
});
