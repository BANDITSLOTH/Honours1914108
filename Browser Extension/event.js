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
