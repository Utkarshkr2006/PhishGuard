// PhishGuard 2.0 - Client Side Scripts

document.addEventListener('DOMContentLoaded', () => {
  const urlForm = document.getElementById('urlForm');
  const urlInput = document.getElementById('urlInput');
  const resultsContainer = document.getElementById('resultsContainer');
  const resultsText = document.getElementById('resultsText');

  if (urlForm) {
    urlForm.addEventListener('submit', (e) => {
      e.preventDefault();
      
      const targetUrl = urlInput.value.trim();
      if (!targetUrl) {
        alert('Please enter a valid URL to analyze.');
        return;
      }

      // Show placeholder response for Task 1
      resultsContainer.style.display = 'block';
      resultsText.textContent = `Target set: "${targetUrl}". Phishing detection and analysis engine will be connected in future steps.`;
    });
  }
});
