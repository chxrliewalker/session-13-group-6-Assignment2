import os
from typing import List
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import joblib
import pandas as pd
from pydantic import BaseModel, Field

# Import Assignment 2 feature extraction function
from feature_extraction import FEATURE_COLUMNS, extract_url_features

# ------------------------------------------------------------------------------
# 1. INITIALIZE FASTAPI & BULLETPROOF CORS SETUP
# ------------------------------------------------------------------------------
app = FastAPI(
    title="Phishing URL Detection API",
    description="Offline-capable API that parses URL mechanics to evaluate threat probability.",
    version="1.0.0",
)

# Universal CORS Middleware (Handles localhost, 127.0.0.1, custom ports, and preflights)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],        # Allow all local origins during development
    allow_credentials=False,    # Disabled to allow wildcard origins without browser rejection
    allow_methods=["*"],        # Allows GET, POST, OPTIONS, PUT, DELETE
    allow_headers=["*"],        # Allows Content-Type, Accept, Authorization, etc.
)

# ------------------------------------------------------------------------------
# 2. LOAD MODEL AT SERVER STARTUP
# ------------------------------------------------------------------------------
MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_pipeline.joblib")
pipeline = None

try:
    if os.path.exists(MODEL_PATH):
        pipeline = joblib.load(MODEL_PATH)
        print(f"[*] Successfully loaded ML pipeline from '{MODEL_PATH}'")
    else:
        print(f"[!] Warning: Model file not found at '{MODEL_PATH}'. Running without loaded pipeline.")
except Exception as e:
    print(f"[!] Critical Error loading model pipeline: {e}")

# ------------------------------------------------------------------------------
# 3. PYDANTIC SCHEMAS (DATA VALIDATION & PAYLOAD SIZE LIMITS)
# ------------------------------------------------------------------------------
class URLRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="Raw URL string to scan",
        json_schema_extra={"example": "http://example.com/login"},
    )

class URLResponse(BaseModel):
    url: str
    verdict: str
    is_phishing: bool
    risk_score_pct: float
    trust_score_pct: float
    risk_flags: List[str]

# ------------------------------------------------------------------------------
# 4. EXPLICIT OPTIONS PREFLIGHT ROUTE (Fixes 400 Bad Request on OPTIONS)
# ------------------------------------------------------------------------------
@app.options("/api/predict")
def options_predict(response: Response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "POST, GET, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "*"
    return Response(status_code=status.HTTP_200_OK)

# ------------------------------------------------------------------------------
# 5. API ROUTES
# ------------------------------------------------------------------------------

# Root Route (Fixes 404 on GET /)
@app.get("/", status_code=status.HTTP_200_OK)
def root():
    return {
        "message": "Welcome to the Phishing URL Detection API",
        "documentation": "Visit /docs for interactive OpenAPI testing",
        "status": "online",
    }

# Method 1: GET - Health check and system status
@app.get("/api/health", status_code=status.HTTP_200_OK)
def health_check():
    return {
        "status": "online",
        "model_loaded": pipeline is not None,
        "service": "Phishing URL Detector Engine",
    }

# Method 2: POST - Scan input URL and run ML prediction
@app.post("/api/predict", response_model=URLResponse, status_code=status.HTTP_200_OK)
def predict_url(payload: URLRequest):
    if pipeline is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model pipeline is not loaded on backend server.",
        )

    url_string = payload.url.strip()

    try:
        # 1. Wrap string in DataFrame and extract static features
        raw_df = pd.DataFrame([{"url": url_string}])
        feature_df = extract_url_features(raw_df, url_column="url")
        X_input = feature_df[["url"] + FEATURE_COLUMNS]

        # 2. Predict probability and binary class
        prediction = int(pipeline.predict(X_input)[0])
        probabilities = pipeline.predict_proba(X_input)

        phishing_prob = (
            float(probabilities[0][1])
            if len(probabilities.shape) > 1 and probabilities.shape[1] > 1
            else float(prediction)
        )
        risk_score = round(phishing_prob * 100, 2)
        trust_score = round((1.0 - phishing_prob) * 100, 2)

        # 3. Extract diagnostic heuristic threat tags
        row = X_input[FEATURE_COLUMNS].iloc[0]
        risk_flags = []
        if row.get("is_ip_address", 0) == 1:
            risk_flags.append("Raw IPv4 Address Host")
        if row.get("is_shortened", 0) == 1:
            risk_flags.append("Known URL Shortener Domain")
        if row.get("count_suspicious_keywords", 0) > 0:
            risk_flags.append(f"Suspicious Security Keywords ({int(row.get('count_suspicious_keywords'))})")
        if row.get("domain_has_prefix_suffix_hyphen", 0) == 1:
            risk_flags.append("Domain Prefix/Suffix Hyphen Deception")
        if row.get("domain_entropy", 0) > 3.8:
            risk_flags.append(f"High Domain Randomness / Entropy ({row.get('domain_entropy'):.2f})")
        if row.get("count_at", 0) > 0:
            risk_flags.append("Embedded Authentication Symbol (@)")

        verdict = "PHISHING / MALICIOUS" if prediction == 1 else "LEGITIMATE / SAFE"

        return URLResponse(
            url=url_string,
            verdict=verdict,
            is_phishing=bool(prediction == 1),
            risk_score_pct=risk_score,
            trust_score_pct=trust_score,
            risk_flags=risk_flags if risk_flags else ["No immediate heuristic risk flags triggered"],
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unable to process or parse URL string: {str(e)}",
        )

# ------------------------------------------------------------------------------
# 6. LOCAL SERVER RUNNER
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
