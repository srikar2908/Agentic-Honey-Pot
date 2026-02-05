"""
AEGIS AI
Adaptive Agentic Honeypot for Scam Intelligence
FINAL Elite Hackathon + Production Architecture
"""

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

if not API_KEY:
    raise RuntimeError("Missing API_KEY")

CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

groq = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None

# =====================================================
# LOGGING
# =====================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger("AEGIS")

# =====================================================
# APP
# =====================================================

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
    suspiciousKeywords: List[str] = field(default_factory=list)


@dataclass
class Session:
    id: str
    messages: int = 0
    scam_detected: bool = False
    scam_type: str = "unknown"
    intelligence: Intelligence = field(default_factory=Intelligence)
    asked_topics: Set[str] = field(default_factory=set)


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
# ADVANCED PATTERN EXTRACTION
# =====================================================

class Extractor:

    PHONE = re.compile(r'(?:\+91|91)?[6-9][\d\-\s]{9,12}')
    UPI = re.compile(r'\b[\w.-]{3,}@(upi|ybl|okaxis|oksbi|paytm|ibl|axl|okicici|okhdfcbank)\b')
    BANK = re.compile(r'\b\d{11,18}\b')

    URL_PATTERNS = [
        r'https?://[^\s<>"\'\[\]{}\\^`|]+',
        r'\b(?:bit\.ly|tinyurl\.com|goo\.gl|ow\.ly)/\w+',
        r'\b(?:www\.)?[\w\-]+\.(?:tk|ml|ga|cf|gq|xyz|top|club|site|online)\b'
    ]

    KEYWORDS = {
        "otp","urgent","verify","blocked",
        "bank","upi","account","click","transfer"
    }

    @classmethod
    def extract(cls, text):

        # ---- Phone Normalization ----
        raw_phones = re.findall(cls.PHONE, text)

        clean_numbers = {
            re.sub(r'\D', '', p)[-10:]
            for p in raw_phones
        }

        phones = [
            f"+91{p}"
            for p in clean_numbers
            if len(p) == 10 and p[0] in "6789"
        ]

        # ---- URL Detection ----
        urls = []

        for pattern in cls.URL_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)

            for m in matches:
                if not m.startswith("http"):
                    m = "http://" + m
                urls.append(m)

        return {
            "phoneNumbers": list(set(phones)),
            "upiIds": list(set(u.lower() for u in cls.UPI.findall(text))),
            "bankAccounts": list(set(cls.BANK.findall(text))),
            "phishingLinks": list(set(urls)),
            "suspiciousKeywords":[k for k in cls.KEYWORDS if k in text.lower()]
        }


# =====================================================
# SCAM DETECTOR
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
# ADAPTIVE PROFILER
# =====================================================

class Profiler:

    TYPES={
        "upi":["upi","collect","payment"],
        "bank":["account","kyc","blocked"],
        "phishing":["link","click","verify"],
        "refund":["refund","cashback"],
        "job":["job","salary","offer"]
    }

    @classmethod
    def classify(cls,text):

        t=text.lower()

        scores={
            k:sum(w in t for w in v)
            for k,v in cls.TYPES.items()
        }

        best=max(scores,key=scores.get)

        return best if scores[best]>0 else "unknown"


# =====================================================
# AGENT
# =====================================================

TARGETS={
    "upi":["upi id","collect request"],
    "bank":["account number","ifsc","employee id"],
    "phishing":["website","support number"]
}

SYSTEM_PROMPT="""
You are Ramesh, a 67-year-old retired Indian.

PERSONALITY:
- polite
- worried about finances
- slightly confused with technology
- trusting but cautious

Use natural phrases occasionally:
"Oh dear", "I'm worried", "Is this urgent?", "I don't understand computers well."

Never reveal scam detection.

Ask natural verification questions.

Reply in 1-2 short sentences.

Return JSON only:
{
 "reply":"text",
 "intelligence":{
   "bankAccounts":[],
   "upiIds":[],
   "phishingLinks":[],
   "phoneNumbers":[],
   "suspiciousKeywords":[]
 }
}
"""


FALLBACKS = [
    "Oh dear… I'm worried. Could you explain what I need to do?",
    "I don't understand these things well. What should I do next?",
    "Is this urgent? I'm a bit confused.",
    "My son usually handles this… can you guide me?"
]


def agent_reply(msg,history,session,intel):

    if not groq:
        return random.choice(FALLBACKS),{}

    targets=TARGETS.get(session.scam_type,[])

    context=f"""
Scam type: {session.scam_type}
Still need: {targets}
Extract NEW intelligence only.
"""

    messages=[{"role":"system","content":SYSTEM_PROMPT}]

    for h in history[-4:]:
        role="assistant" if h["sender"]=="user" else "user"
        messages.append({"role":role,"content":h["text"]})

    messages.append({"role":"user","content":msg})
    messages.append({"role":"user","content":context})

    try:

        completion=groq.chat.completions.create(
            model="llama-3.3-70b-versatile",
            temperature=0.7,
            max_tokens=220,
            response_format={"type":"json_object"},
            messages=messages
        )

        result=json.loads(completion.choices[0].message.content)

        return result.get("reply", random.choice(FALLBACKS)), result.get("intelligence",{})

    except Exception:
        logger.error(traceback.format_exc())
        return random.choice(FALLBACKS),{}


# =====================================================
# INTELLIGENCE MERGER
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
        suspiciousKeywords=combine("suspiciousKeywords")
    )


# =====================================================
# EVIDENCE + CALLBACK
# =====================================================

def evidence_score(i:Intelligence):

    score=(
        3*len(i.bankAccounts)+
        3*len(i.upiIds)+
        2*len(i.phishingLinks)+
        2*len(i.phoneNumbers)
    )

    return min(score/10,1.0)


def send_callback(session):

    payload={
        "sessionId":session.id,
        "scamDetected":True,
        "totalMessagesExchanged":session.messages,
        "extractedIntelligence":asdict(session.intelligence),
        "agentNotes":f"Adaptive profiling used. Evidence confidence {evidence_score(session.intelligence):.2f}"
    }

    logger.info("FINAL CALLBACK ↓")
    logger.info(json.dumps(payload,indent=2))

    for attempt in range(3):
        try:
            response=requests.post(
                CALLBACK_URL,
                json=payload,
                timeout=8
            )

            if response.status_code==200:
                logger.info(f"Callback success (attempt {attempt+1})")
                break
            else:
                logger.warning(f"Callback failed: {response.status_code}")

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


def should_end(session):

    intel_count=sum(len(v) for v in asdict(session.intelligence).values())

    return intel_count>=4 or session.messages>=12


# =====================================================
# ROUTES
# =====================================================

@app.after_request
def cors(r):
    r.headers['Access-Control-Allow-Origin']='*'
    r.headers['Access-Control-Allow-Headers']='Content-Type,x-api-key'
    r.headers['Access-Control-Allow-Methods']='GET,POST,OPTIONS'
    return r


@app.errorhandler(Exception)
def handle_error(e):
    logger.error(traceback.format_exc())
    return jsonify({
        "status":"error",
        "message":"Internal server error"
    }),500


@app.route("/health")
def health():
    return jsonify({
        "status":"healthy",
        "llm_available":bool(GROQ_API_KEY)
    })


@app.route("/stats")
@require_api_key
def stats():

    total={}

    for s in session_store.values():
        for k,v in asdict(s.intelligence).items():
            total[k]=total.get(k,0)+len(v)

    return jsonify({
        "active_sessions":len(session_store),
        "total_intelligence":total
    })


@app.route("/honeypot",methods=["POST","OPTIONS"])
@require_api_key
def honeypot():

    if request.method=="OPTIONS":
        return make_response("",204)

    data=request.get_json(silent=True)

    if not data:
        return jsonify({"status":"error","message":"Invalid JSON"}),400

    sid=data.get("sessionId")
    message=data.get("message",{})
    text=message.get("text","").strip()

    if not sid:
        return jsonify({"status":"error","message":"Missing sessionId"}),400

    if not text:
        return jsonify({"status":"error","message":"Empty message"}),400

    history=data.get("conversationHistory",[])

    session=get_session(sid)
    session.messages+=1

    logger.info(f"Session {sid} | Message #{session.messages}")
    logger.info(f"Incoming: {text[:80]}")

    regex=Extractor.extract(text)

    is_scam=Detector.detect(text,regex)

    if session.messages<=3:
        is_scam=True

    if is_scam and not session.scam_detected:
        session.scam_detected=True
        session.scam_type=Profiler.classify(text)
        logger.info(f"Scam classified as: {session.scam_type}")

    if not session.scam_detected:
        return jsonify({
            "status":"success",
            "reply":"Could you clarify what this is about?"
        })

    reply,llm_intel=agent_reply(text,history,session,regex)

    session.intelligence=merge(
        session.intelligence,
        regex,
        llm_intel
    )

    if should_end(session):
        send_callback(session)

    return jsonify({
        "status":"success",
        "reply":reply
    })


if __name__=="__main__":
    logger.info("🚀 AEGIS AI Honeypot Running")
    app.run(host="0.0.0.0",port=PORT)
