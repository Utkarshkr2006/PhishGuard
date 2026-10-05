import logging
from flask import Flask, render_template, request

from analysis.predictor import predict_url
from analysis.explainability import explain_prediction
from analysis.risk_scoring import calculate_risk_score

app = Flask(__name__)
app.config['DEBUG'] = False
logging.basicConfig(level=logging.INFO)

@app.route('/', methods=['GET'])
def home():
    """
    Renders the PhishGuard 2.0 URL analysis homepage.
    """
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    """
    Processes submitted URL string through the PhishGuard analysis pipeline:
    predict_url() -> explain_prediction() -> calculate_risk_score()
    
    Operates 100% offline — zero network calls or HTTP requests to target URL.
    """
    raw_url = request.form.get('url', '')
    
    # Input Validation
    if not raw_url or not raw_url.strip():
        return render_template(
            'index.html',
            error="Please enter a valid, non-empty URL string to analyze."
        ), 400
        
    url = raw_url.strip()
    
    if len(url) > 2048:
        return render_template(
            'index.html',
            error="URL exceeds maximum length limit of 2048 characters."
        ), 400

    try:
        # Modular Pipeline Execution
        prediction_result = predict_url(url)
        explanation_result = explain_prediction(prediction_result)
        risk_result = calculate_risk_score(prediction_result, explanation_result)

        return render_template(
            'result.html',
            url=url,
            prediction_result=prediction_result,
            explanation_result=explanation_result,
            risk_result=risk_result
        )
    except Exception as e:
        # Sanitize logged URL to avoid logging potential credentials or overflowing logs
        safe_url = url.split('@')[-1] if '@' in url else url
        safe_log_url = safe_url[:80] + ('...' if len(safe_url) > 80 else '')
        app.logger.error("Internal analysis error for URL '%s': %s", safe_log_url, e, exc_info=True)
        return render_template(
            'index.html',
            error="An internal analysis error occurred. Please try again."
        ), 500

if __name__ == '__main__':
    # Debug mode explicitly disabled for normal execution
    app.run(debug=False, host='127.0.0.1', port=5000)

