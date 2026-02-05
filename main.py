import os
import re
import json
import logging
import traceback
import random
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Set
from threading import Lock
from functools import wraps

from flask import Flask, request, jsonify, make_response
from groq import Groq
import requests
from dotenv import load_dotenv

load_dotenv()

# =====================================================
# CONFIG
# =====================================================

API_KEY = os.getenv("API_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
PORT = int(os.getenv("PORT", 5000))

CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

if not API_KEY:
    raise RuntimeError("Missing API_KEY")

groq = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AEGIS")

app = Flask(__name__)

session_store: Dict[str, "Session"] = {}
lock = Lock()

# =====================================================
# DATA MODELS
# =====================================================

@dataclass
class Intelligence:
    bankAccounts: List[str] = field(default_factory=list)
    upiIds: List[str] = field(default_factory=list)
    phishingLinks: List[str] = field(default_factory=list)
    phoneNumbers: List[str] = field(default_factory=list)
    ifscCodes: List[str] = field(default_factory=list)
    suspiciousKeywords: List[str] = field(default_factory=list)


@dataclass
class Session:
    id: str
    messages: int = 0
    scam_detected: bool = False
    scam_type: str = "unknown"
    intelligence: Intelligence = field(default_factory=Intelligence)
    seen_messages: Set[str] = field(default_factory=set)

# =====================================================
# AUTH
# =====================================================

def require_api_key(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.headers.get("x-api-key") != API_KEY:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper


# =====================================================
# EXTRACTOR (ELITE VERSION)
# =====================================================

class Extractor:

    PHONE = re.compile(r'(?:\+91|91)?[6-9][\d\-\s]{9,12}')
    BANK = re.compile(r'\b\d{11,18}\b')
    IFSC = re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b', re.I)

    # ✅ FIXED UPI REGEX
    UPI = re.compile(
        r'\b([\w\.\-]{3,}@(upi|ybl|okaxis|oksbi|paytm|ibl|axl|okicici|okhdfcbank))\b',
        re.I
    )

    URL_PATTERNS = [
        r'https?://[^\s<>"]+',
        r'\b(?:bit\.ly|tinyurl\.com|goo\.gl|ow\.ly)/\w+',
        r'\b(?:www\.)?[\w\-]+\.(?:tk|ml|ga|cf|gq|xyz|top|club|site|online)\b'
    ]

    KEYWORDS = {
        "otp","urgent","verify","blocked",
        "bank","upi","account","click","transfer"
    }

    @classmethod
    def extract(cls, text):

        # Phone normalization
        raw = re.findall(cls.PHONE, text)

        phones = {
            "+91" + re.sub(r'\D','',p)[-10:]
            for p in raw
            if len(re.sub(r'\D','',p)[-10:]) == 10
        }

        # URLs
        urls = []
        for pattern in cls.URL_PATTERNS:
            matches = re.findall(pattern, text, re.I)
            for m in matches:
                if not m.startswith("http"):
                    m = "http://" + m
                urls.append(m)

        # UPI FIX
        upis = [u[0].lower() for u in re.findall(cls.UPI, text)]

        return {
            "phoneNumbers": list(set(phones)),
            "upiIds": list(set(upis)),
            "bankAccounts": list(set(cls.BANK.findall(text))),
            "ifscCodes": list(set(cls.IFSC.findall(text))),
            "phishingLinks": list(set(urls)),
            "suspiciousKeywords":[k for k in cls.KEYWORDS if k in text.lower()]
        }


# =====================================================
# DETECTOR
# =====================================================

class Detector:

    HIGH={"otp","pin","password","cvv"}
    MED={"urgent","blocked","verify"}
    CTX={"bank","account","payment","upi","transfer"}

    @classmethod
    def detect(cls,text,intel):

        t=text.lower()

        score=(
            0.3*sum(w in t for w in cls.HIGH)+
            0.15*sum(w in t for w in cls.MED)+
            0.1*sum(w in t for w in cls.CTX)
        )

        if intel["phishingLinks"]:
            score+=0.2

        if intel["phoneNumbers"]:
            score+=0.15

        return score>=0.35


# =====================================================
# AGENT
# =====================================================

FALLBACKS=[
    "Oh dear… could you explain what I need to do?",
    "I'm worried. Is this urgent?",
    "I don't understand computers well, please guide me."
]

SYSTEM_PROMPT="""
You are Ramesh, a 67-year-old retired Indian.

Be polite, worried, slightly confused.
Never reveal scam detection.
Ask for verification details naturally.
Return JSON with reply + intelligence.
"""

def agent_reply(msg,history,session,intel):

    if not groq:
        return random.choice(FALLBACKS),{}

    messages=[{"role":"system","content":SYSTEM_PROMPT}]

    for h in history[-4:]:
        role="assistant" if h["sender"]=="user" else "user"
        messages.append({"role":role,"content":h["text"]})

    messages.append({"role":"user","content":msg})

    try:

        completion=groq.chat.completions.create(
            model="llama-3.3-70b-versatile",
            temperature=0.7,
            max_tokens=200,
            response_format={"type":"json_object"},
            messages=messages
        )

        result=json.loads(completion.choices[0].message.content)

        return result.get("reply",random.choice(FALLBACKS)), result.get("intelligence",{})

    except Exception:
        logger.error(traceback.format_exc())
        return random.choice(FALLBACKS),{}


# =====================================================
# MERGER
# =====================================================

def merge(existing,*sources):

    def combine(k):
        data=set(getattr(existing,k))
        for s in sources:
            data.update(s.get(k,[]))
        return list(data)

    return Intelligence(
        bankAccounts=combine("bankAccounts"),
        upiIds=combine("upiIds"),
        phishingLinks=combine("phishingLinks"),
        phoneNumbers=combine("phoneNumbers"),
        ifscCodes=combine("ifscCodes"),
        suspiciousKeywords=combine("suspiciousKeywords")
    )


# =====================================================
# TERMINATION (FIXED)
# =====================================================

def should_end(session):

    intel_score=(
        len(session.intelligence.bankAccounts)*3+
        len(session.intelligence.upiIds)*3+
        len(session.intelligence.phoneNumbers)*2+
        len(session.intelligence.phishingLinks)*2
    )

    if session.messages < 8:
        return False

    if session.messages >= 15:
        return True

    if intel_score >= 8:
        return True

    return False


# =====================================================
# EVIDENCE
# =====================================================

def evidence_score(i:Intelligence):

    score=(
        len(i.bankAccounts)*0.35+
        len(i.upiIds)*0.35+
        len(i.phoneNumbers)*0.15+
        len(i.phishingLinks)*0.15
    )

    return round(min(score,0.95),2)


# =====================================================
# CALLBACK
# =====================================================

def send_callback(session):

    payload={
        "sessionId":session.id,
        "scamDetected":True,
        "totalMessagesExchanged":session.messages,
        "extractedIntelligence":asdict(session.intelligence),
        "agentNotes":f"Scam confidence: {evidence_score(session.intelligence)}"
    }

    for attempt in range(3):
        try:
            r=requests.post(CALLBACK_URL,json=payload,timeout=8)
            if r.status_code==200:
                break
        except Exception:
            logger.error(traceback.format_exc())

    with lock:
        session_store.pop(session.id,None)


# =====================================================
# SESSION
# =====================================================

def get_session(sid):

    with lock:
        if sid not in session_store:
            session_store[sid]=Session(id=sid)
        return session_store[sid]


# =====================================================
# ROUTES
# =====================================================

@app.route("/health")
def health():
    return jsonify({"status":"healthy"})


@app.route("/honeypot",methods=["GET","POST","OPTIONS"])
@require_api_key
def honeypot():

    if request.method=="GET":
        return jsonify({"status":"active","service":"AEGIS Honeypot"})

    if request.method=="OPTIONS":
        return make_response("",204)

    data=request.get_json(silent=True)

    if not data:
        return jsonify({"status":"error","message":"Invalid JSON"}),400

    sid=data.get("sessionId")
    text=data.get("message",{}).get("text","").strip()

    if not sid or not text:
        return jsonify({"status":"error","message":"Missing fields"}),400

    session=get_session(sid)

    # dedup guard
    if text in session.seen_messages:
        return jsonify({"status":"success","reply":"Please provide new details for verification."})

    session.seen_messages.add(text)
    session.messages+=1

    regex=Extractor.extract(text)

    is_scam=Detector.detect(text,regex)

    if session.messages<=5:
        is_scam=True

    if is_scam:
        session.scam_detected=True

    reply,llm_intel=agent_reply(
        text,
        data.get("conversationHistory",[]),
        session,
        regex
    )

    session.intelligence=merge(session.intelligence,regex,llm_intel)

    if should_end(session):
        send_callback(session)

    return jsonify({"status":"success","reply":reply})


if __name__=="__main__":
    app.run(host="0.0.0.0",port=PORT)
