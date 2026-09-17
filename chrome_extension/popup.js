// Backend API URL (Change to your Render URL when deploying)
const API_URL = "https://ai-based-phishing-detection-el4j.onrender.com/api/scan/url";
// For local testing: const API_URL = "http://127.0.0.1:5000/api/scan/url";

let currentTabUrl = "";

// Get current tab URL when popup opens
chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
    let tab = tabs[0];
    currentTabUrl = tab.url;
    
    // Truncate URL for display
    let displayUrl = currentTabUrl.length > 50 ? currentTabUrl.substring(0, 47) + "..." : currentTabUrl;
    document.getElementById("currentUrl").innerText = displayUrl;
});

document.getElementById("scanBtn").addEventListener("click", async () => {
    const btn = document.getElementById("scanBtn");
    const loader = document.getElementById("loader");
    const resultBox = document.getElementById("resultBox");

    // UI Reset
    btn.disabled = true;
    loader.style.display = "block";
    resultBox.style.display = "none";

    try {
        const response = await fetch(API_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: currentTabUrl })
        });

        const data = await response.json();

        if (response.ok) {
            resultBox.style.display = "block";
            let isSafe = data.is_safe;
            
            resultBox.className = isSafe ? "safe" : "danger";
            
            let reasonsHtml = data.reasons.length > 0 
                ? `<ul style="margin-top: 8px; padding-left: 20px;"><li>${data.reasons.slice(0,2).join("</li><li>")}</li></ul>` 
                : "";

            resultBox.innerHTML = `
                <div class="score">${data.threat_score.toFixed(1)}% Risk (${data.risk_level})</div>
                <div>${isSafe ? 'No active threats found on this page.' : 'Warning! Deceptive patterns detected.'}</div>
                ${reasonsHtml}
            `;
        } else {
            resultBox.style.display = "block";
            resultBox.className = "danger";
            resultBox.innerHTML = `Error: ${data.error || 'Server unreachable.'}`;
        }
    } catch (err) {
        resultBox.style.display = "block";
        resultBox.className = "danger";
        resultBox.innerHTML = `Network Error: Could not connect to PhishShield Server.`;
    } finally {
        btn.disabled = false;
        loader.style.display = "none";
    }
});
