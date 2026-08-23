from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel

# Existing URL-risk pipeline
from app.feature_extractor import extract_features
from app.agent import decide
from app.model_loader import lr_model, rf_model, xgb_model
from app.utils import track_ip

# Security / behavior pipeline
from app.database import init_db, get_db
from app.security_middleware import IPBlockMiddleware
from app.request_logging_middleware import RequestLoggingMiddleware
from app.db_models import SecurityAlert, RequestLog

app = FastAPI()

# ============================================================
# CORS CONFIGURATION
# ============================================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows requests from Vite (ports 5173 / 5174)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# CUSTOM MIDDLEWARE
# ============================================================
from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

app = FastAPI()

# 1. Custom Middlewares registered first (run innermost)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(IPBlockMiddleware)

# 2. CORS Middleware registered LAST (runs outermost so it handles preflight OPTIONS requests)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# DATABASE INITIALIZATION
# ============================================================
@app.on_event("startup")
def _init_security_db():
    init_db()

# Request model for JSON payloads sent from React
class URLPayload(BaseModel):
    url: str

# ============================================================
# CORE ENDPOINTS
# ============================================================

@app.get("/")
def home():
    return {"message": "Chakravyuh API running 🚀"}

@app.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    """Provides system stats to the frontend dashboard header."""
    try:
        total_logs = db.query(RequestLog).count()
    except Exception:
        total_logs = 0
    return {
        "status": "running",
        "total_requests": total_logs
    }

@app.get("/alerts")
def list_alerts(db: Session = Depends(get_db)):
    """Fetch recorded security alerts for the dashboard."""
    alerts = (
        db.query(SecurityAlert)
        .order_by(SecurityAlert.created_at.desc())
        .limit(100)
        .all()
    )

    return [
        {
            "id": a.id,
            "session_id": a.session_id,
            "ip": a.ip,
            "prediction": a.prediction,
            "confidence": a.confidence,
            "action": a.action,
            "reason": a.reason,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "is_read": a.is_read,
        }
        for a in alerts
    ]

def confidence_label(score: float):
    if score > 0.8:
        return "HIGH RISK"
    elif score > 0.4:
        return "MEDIUM RISK"
    else:
        return "LOW RISK"

# ============================================================
# ANALYSIS / PREDICTION ENDPOINTS
# ============================================================

@app.post("/analyze")
@app.post("/predict")
def analyze_url(payload: URLPayload, request: Request):
    """Processes URL risk evaluation for both frontend /analyze and /predict."""
    url = payload.url

    try:
        # Step 1: Feature Extraction
        features = extract_features(url)

        # Step 2: Model Inferences
        lr_score = lr_model.predict_proba([features])[0][1]
        rf_score = rf_model.predict_proba([features])[0][1]
        xgb_score = xgb_model.predict_proba([features])[0][1]

        # Step 3: Combined Ensemble Score
        final_score = (lr_score + rf_score + xgb_score) / 3

        # Step 4: Decision Logic
        action, reasons = decide(final_score, url)

        # Step 5: Risk Alignment
        if action == "BLOCK":
            risk = "HIGH RISK"
        elif action == "ALERT":
            risk = "MEDIUM RISK"
        else:
            risk = confidence_label(final_score)

        # Step 6: Tracking IP & Rate Limits
        client_ip = request.client.host
        request_count = track_ip(client_ip)

        if request_count > 10:
            reasons.append("Too many requests from same user")
            action = "ALERT"
            risk = "MEDIUM RISK"

        return {
            "url": url,
            "score": float(final_score),
            "final_score": float(final_score),
            "risk_level": risk,
            "action": action,
            "reasons": reasons,
            "request_count": request_count,
            "model_confidence": {
                "logistic_regression": float(lr_score),
                "random_forest": float(rf_score),
                "xgboost": float(xgb_score)
            }
        }

    except Exception as e:
        return {"error": str(e), "score": 0.5}