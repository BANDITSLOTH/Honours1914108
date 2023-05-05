chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {
    if (request.action === 'detectPhishing') {
        fetch('http://localhost:5000/detect_phishing', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: request.url })
        })
            .then(response => response.json())
            .then(data => sendResponse(data))
            .catch(error => console.error(error));
        return true;
    }
});
