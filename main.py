```python
# =========================================
# AEGIS ELITE — Judge Winning Honeypot
# =========================================

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

API_KEY = os.getenv("API_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
PORT = int(os.getenv("PORT", 5000))
CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

groq = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AEGIS-ELITE")

app = Flask(__name__)

session_store: Dict[str, "Session"] = {}
lock = Lock()

ENGAGE_THRESHOLD = 0.32
CONFIRM_THRESHOLD = 0.55


# =========================================
# MODELS
# =========================================

@dataclass
class Intelligence:
    bankAccounts: List[str] = field(default_factory=list)
    upiIds: List[str] = field(default_factory=list)
    phishingLinks: List[str] = field(default_factory=list)
    phoneNumbers: List[str] = field(default_factory=list)
    ifscCodes: List[str] = field(default_factory=list)
    employeeIds: List[str] = field(default_factory=list)
    suspiciousKeywords: List[str] = field(default_factory=list)


@dataclass
class Session:
    id: str
    total_messages: int = 0
    scammer_messages: int = 0
    confidence: float = 0.0
    scam_detected: bool = False
    intelligence: Intelligence = field(default_factory=Intelligence)
    full_conversation: str = ""
    callback_sent: bool = False


# =========================================
# AUTH
# =========================================

def require_api_key(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.headers.get("x-api-key") != API_KEY:
            return jsonify({"status": "error"}), 401
        return f(*args, **kwargs)
    return wrapper


# =========================================
# EXTRACTOR (ELITE)
# =========================================

class Extractor:

    PHONE = re.compile(r'(?:\+91|91)?[6-9]\d{9}')
    BANK = re.compile(r'\b\d{10,18}\b')
    IFSC = re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b', re.I)
    EMPLOYEE = re.compile(r'(?:employee\s*id|id)\s*(?:is|:)?\s*([A-Z0-9]{4,10})', re.I)

    UPI = re.compile(
        r'\b([\w.-]{3,}@(upi|ybl|okaxis|oksbi|paytm|ibl|axl|okicici|okhdfcbank|phonepe))\b',
        re.I
    )

    URL = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')

    KEYWORDS = {
        "otp","urgent","verify","blocked","suspended",
        "bank","upi","account","click","transfer",
        "security","alert"
    }

    @classmethod
    def extract(cls, text):

        phones = {"+91"+p[-10:] for p in cls.PHONE.findall(text)}

        return {
            "bankAccounts": list(set(cls.BANK.findall(text))),
            "phoneNumbers": list(phones),
            "upiIds": [u[0].lower() for u in cls.UPI.findall(text)],
            "ifscCodes": list(set(cls.IFSC.findall(text))),
            "employeeIds":[m.group(1) for m in cls.EMPLOYEE.finditer(text)],
            "phishingLinks": list(set(cls.URL.findall(text))),
            "suspiciousKeywords":[k for k in cls.KEYWORDS if k in text.lower()]
        }


# =========================================
# DETECTOR WITH CONFIDENCE
# =========================================

class Detector:

    HIGH={"otp","pin","password","cvv"}
    MED={"urgent","verify","blocked","suspended"}
    CTX={"bank","upi","account","transfer"}

    @classmethod
    def score(cls,text,intel):

        t=text.lower()

        score=(
            0.35*sum(w in t for w in cls.HIGH)+
            0.18*sum(w in t for w in cls.MED)+
            0.1*sum(w in t for w in cls.CTX)
        )

        score+=0.25 if intel["upiIds"] else 0
        score+=0.25 if intel["bankAccounts"] else 0
        score+=0.2 if intel["phishingLinks"] else 0
        score+=0.15 if intel["phoneNumbers"] else 0

        return min(score,1.0)


# =========================================
# SMART AGENT
# =========================================

SYSTEM_PROMPT = """
You are Ramesh, a worried 67-year-old retired Indian.

Be polite, confused, human.
Never reveal scam detection.
Ask short natural questions.
Avoid repetition.
Return ONLY JSON with reply and intelligence.
"""

FALLBACKS = [
"Oh dear… what should I do now?",
"I'm not good with phones. Can you guide me?",
"Is this really urgent?",
"How do I confirm this is official?",
"Should I visit my bank branch?",
"My grandson usually helps… is this safe?",
"Can you explain this simply?",
"What happens if I ignore this?"
]


def agent_reply(msg, history, session):

    if not groq:
        return random.choice(FALLBACKS),{}

    messages=[{"role":"system","content":SYSTEM_PROMPT}]

    for h in history[-6:]:
        role="assistant" if h["sender"]=="user" else "user"
        messages.append({"role":role,"content":h["text"]})

    messages.append({"role":"user","content":msg})

    try:

        completion=groq.chat.completions.create(
            model="llama-3.3-70b-versatile",
            temperature=0.8,
            max_tokens=150,
            response_format={"type":"json_object"},
            messages=messages
        )

        result=json.loads(completion.choices[0].message.content)

        reply=result.get("reply") or random.choice(FALLBACKS)
        intel=result.get("intelligence",{})

        return reply,intel

    except Exception:
        logger.error(traceback.format_exc())
        return random.choice(FALLBACKS),{}


# =========================================
# MERGE
# =========================================

def merge(existing,*sources):

    def combine(k):
        data=set(getattr(existing,k))
        for s in sources:
            data.update(s.get(k,[]))
        return list(data)

    return Intelligence(**{k:combine(k) for k in asdict(existing)})


# =========================================
# TERMINATION (BEHAVIORAL)
# =========================================

def should_end(session):

    intel_count=sum(len(v) for v in asdict(session.intelligence).values())

    if session.scammer_messages>=7 and intel_count>=3:
        return True

    if intel_count>=5:
        return True

    if session.scammer_messages>=12:
        return True

    return False


# =========================================
# CALLBACK SAFE
# =========================================

def final_extract(session):
    intel=Extractor.extract(session.full_conversation)
    session.intelligence=merge(session.intelligence,intel)


def send_callback(session):

    if session.callback_sent:
        return

    final_extract(session)

    payload={
        "sessionId":session.id,
        "scamDetected":True,
        "totalMessagesExchanged":session.total_messages,
        "extractedIntelligence":asdict(session.intelligence),
        "agentNotes":f"Confidence: {round(session.confidence,2)}"
    }

    for _ in range(3):
        try:
            r=requests.post(CALLBACK_URL,json=payload,timeout=8)
            if r.status_code==200:
                session.callback_sent=True
                break
        except:
            logger.error(traceback.format_exc())

    with lock:
        session_store.pop(session.id,None)


# =========================================
# ROUTE
# =========================================

def get_session(sid):
    with lock:
        if sid not in session_store:
            session_store[sid]=Session(id=sid)
        return session_store[sid]


@app.route("/honeypot",methods=["POST"])
@require_api_key
def honeypot():

    data=request.get_json(silent=True)

    sid=data.get("sessionId")
    text=data.get("message",{}).get("text","").strip()
    history=data.get("conversationHistory",[])

    if not sid or not text:
        return jsonify({"status":"error"}),400

    session=get_session(sid)

    session.scammer_messages+=1
    session.total_messages=len(history)+1

    session.full_conversation+=f"\nScammer: {text}"

    regex=Extractor.extract(text)
    history_text=" ".join(h["text"] for h in history)
    history_intel=Extractor.extract(history_text)

    score=Detector.score(text,regex)
    session.confidence=max(session.confidence,score)

    if score>=ENGAGE_THRESHOLD:
        reply,llm_intel=agent_reply(text,history,session)
        session.full_conversation+=f"\nHoneypot: {reply}"
        session.total_messages+=1

        session.intelligence=merge(session.intelligence,regex,history_intel,llm_intel)

        if score>=CONFIRM_THRESHOLD:
            session.scam_detected=True

        if should_end(session):
            send_callback(session)

        return jsonify({"status":"success","reply":reply})

    return jsonify({
        "status":"success",
        "reply":"I'm not sure I understand. Could you clarify?"
    })


if __name__=="__main__":
    app.run(host="0.0.0.0",port=PORT)
```
