var toggleButton = document.getElementById("toggle-button");
var toggleIcon = document.getElementById("toggle-icon");
var toggleText = document.getElementById("toggle-text");

toggleButton.addEventListener("click", function () {
    if (toggleText.innerHTML === "Click to Enable Detector") {
        toggleText.innerHTML = "Click to Disable Detector";
        togglePhishingDetector(true);
    } else {
        toggleText.innerHTML = "Click to Enable Detector";
        togglePhishingDetector(false);
    }
});

toggleButton.addEventListener("click", function () {
    if (toggleIcon.getAttribute("src") === "enable.png") {
        toggleIcon.setAttribute("src", "disable.png");
        toggleIcon.setAttribute("alt", "Disabled");
    } else {
        toggleIcon.setAttribute("src", "enable.png");
        toggleIcon.setAttribute("alt", "Enabled");
    }
});

function togglePhishingDetector(enabled) {
    if (enabled) {
        fetch('http://localhost:5000/detect_phishing', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ enabled: enabled })
        })
    }
    else {
        fetch('http://localhost:5000/detect_phishing/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ enabled: enabled })
        })
            .then(response => response.json())
            .then(data => console.log(data))
            .catch(error => console.error(error));
    }
}
