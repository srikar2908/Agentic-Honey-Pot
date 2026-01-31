from fastapi import FastAPI, Header, HTTPException, BackgroundTasks, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Tuple
import os
import re
import requests
import logging
from datetime import datetime
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from groq import Groq

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Agentic Honeypot API", version="1.0.0")

# CORS middleware - Allow all origins (required for GUVI tester)
# Note: allow_credentials=True cannot be used with wildcard origins
# The API key authentication provides security, not credentials
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow any origin
    allow_credentials=False,  # Must be False when using wildcard origins
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

# Debug: Log raw request body for 422 errors
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    try:
        body = await request.json()
        logger.error(f"❌ 422 Validation Error. Incoming Body: {body}")
    except:
        logger.error("❌ 422 Validation Error. Could not parse body.")
    
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors(), "body": body if 'body' in locals() else "Unparseable"}
    )

# API Keys - Load from environment variables
HONEYPOT_API_KEY = os.getenv("HONEYPOT_API_KEY", "your-secret-honeypot-key-12345")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")  # Set this in .env file
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# Initialize Groq client
groq_client = Groq(api_key=GROQ_API_KEY)

# In-memory session storage (use Redis in production)
sessions: Dict[str, dict] = {}

# Pydantic Models with flexible configuration
class Message(BaseModel):
    sender: str
    text: str
    timestamp: Optional[str] = None # Make timestamp optional as it's not critical
    
    model_config = ConfigDict(populate_by_name=True)

class Metadata(BaseModel):
    channel: Optional[str] = "SMS"
    language: Optional[str] = "English"
    locale: Optional[str] = "IN"
    
    model_config = ConfigDict(populate_by_name=True)

class HoneypotRequest(BaseModel):
    sessionId: str = Field(..., alias="session_id") # Allow session_id too
    message: Message
    conversationHistory: List[Message] = Field(default=[], alias="conversation_history") # Allow snake_case
    metadata: Optional[Metadata] = None
    
    model_config = ConfigDict(populate_by_name=True)

class HoneypotResponse(BaseModel):
    status: str
    reply: str

# ==================== SCAM DETECTION MODULE ====================

class ScamDetector:
    """Advanced multi-signal scam detection"""
    
    URGENT_KEYWORDS = [
        "urgent", "immediately", "asap", "hurry", "quick", "fast",
        "now", "today", "expire", "limited time", "last chance"
    ]
    
    THREAT_KEYWORDS = [
        "blocked", "suspended", "deactivated", "frozen", "locked",
        "terminated", "cancelled", "closed", "restrict"
    ]
    
    FINANCIAL_KEYWORDS = [
        "bank account", "upi", "payment", "refund", "cashback",
        "prize", "lottery", "reward", "offer", "discount", "free"
    ]
    
    SENSITIVE_REQUESTS = [
        "account number", "upi id", "cvv", "otp", "pin", "password",
        "card number", "ifsc", "verify", "confirm", "update", "kyc"
    ]
    
    AUTHORITY_IMPERSONATION = [
        "bank", "rbi", "income tax", "government", "police",
        "cyber cell", "customer care", "support team", "official"
    ]
    
    @staticmethod
    def calculate_scam_score(message: str, conversation_history: List[Message]) -> int:
        """Calculate scam probability score (0-100)"""
        score = 0
        msg_lower = message.lower()
        
        # 1. Urgency detection (30 points)
        urgency_count = sum(1 for word in ScamDetector.URGENT_KEYWORDS if word in msg_lower)
        score += min(urgency_count * 15, 30)
        
        # 2. Threat language (25 points)
        threat_count = sum(1 for word in ScamDetector.THREAT_KEYWORDS if word in msg_lower)
        score += min(threat_count * 12, 25)
        
        # 3. Requests sensitive information (35 points)
        sensitive_count = sum(1 for word in ScamDetector.SENSITIVE_REQUESTS if word in msg_lower)
        score += min(sensitive_count * 17, 35)
        
        # 4. Contains URL (15 points)
        if re.search(r'http[s]?://|bit\.ly|tinyurl|shortened', msg_lower):
            score += 15
        
        # 5. Authority impersonation (20 points)
        authority_count = sum(1 for word in ScamDetector.AUTHORITY_IMPERSONATION if word in msg_lower)
        score += min(authority_count * 10, 20)
        
        # 6. Financial terms (15 points)
        financial_count = sum(1 for word in ScamDetector.FINANCIAL_KEYWORDS if word in msg_lower)
        score += min(financial_count * 7, 15)
        
        # 7. First message bonus (10 points if first message is suspicious)
        if len(conversation_history) == 0 and score > 30:
            score += 10
        
        # 8. Pattern analysis - combined urgency + sensitive info (20 points bonus)
        if urgency_count > 0 and sensitive_count > 0:
            score += 20
        
        return min(score, 100)
    
    @staticmethod
    def detect_scam(message: str, conversation_history: List[Message]) -> tuple[bool, int]:
        """Returns (is_scam, confidence_score)"""
        score = ScamDetector.calculate_scam_score(message, conversation_history)
        
        # Threshold for scam detection
        SCAM_THRESHOLD = 55  # Balanced threshold for accuracy
        
        is_scam = score >= SCAM_THRESHOLD
        logger.info(f"Scam Detection - Score: {score}, Is Scam: {is_scam}")
        
        return is_scam, score

# ==================== INTELLIGENCE EXTRACTION MODULE ====================

class IntelligenceExtractor:
    """Extract scam intelligence from messages"""
    
    PATTERNS = {
        "bank_account": r'\b\d{9,18}\b',
        "ifsc_code": r'\b[A-Z]{4}0[A-Z0-9]{6}\b',
        "upi_id": r'\b[\w\.\-]+@[\w\.\-]+\b',
        "phone_india": r'(?:\+91[\s-]?)?[6-9]\d{9}\b',
        "url": r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
        "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    }
    
    @staticmethod
    def extract(text: str, intelligence: dict):
        """Extract all intelligence from text"""
        
        # Bank accounts (9-18 digits)
        bank_accounts = re.findall(IntelligenceExtractor.PATTERNS["bank_account"], text)
        intelligence["bankAccounts"].extend(bank_accounts)
        
        # UPI IDs
        potential_upis = re.findall(IntelligenceExtractor.PATTERNS["upi_id"], text)
        # Filter to ensure it's actually UPI format (something@something)
        upis = [u for u in potential_upis if '@' in u and len(u.split('@')[0]) > 2]
        intelligence["upiIds"].extend(upis)
        
        # Phone numbers
        phones = re.findall(IntelligenceExtractor.PATTERNS["phone_india"], text)
        intelligence["phoneNumbers"].extend(phones)
        
        # URLs/Links
        urls = re.findall(IntelligenceExtractor.PATTERNS["url"], text)
        intelligence["phishingLinks"].extend(urls)
        
        # Suspicious keywords
        all_keywords = (
            ScamDetector.URGENT_KEYWORDS +
            ScamDetector.THREAT_KEYWORDS +
            ScamDetector.SENSITIVE_REQUESTS
        )
        text_lower = text.lower()
        found_keywords = [kw for kw in all_keywords if kw in text_lower]
        intelligence["suspiciousKeywords"].extend(found_keywords)
        
        # Remove duplicates
        for key in intelligence:
            intelligence[key] = list(set(intelligence[key]))
        
        logger.info(f"Extracted Intelligence: {intelligence}")

# ==================== AI AGENT MODULE ====================

class HoneypotAgent:
    """Autonomous AI agent using Groq for fast inference"""
    
    PERSONA_TEMPLATE = """You are roleplaying as a realistic person who received a suspicious message. Your goal is to extract information from the sender without revealing you know it's a scam.

PERSONA TRAITS:
- Age: 35-50 years old, middle-class Indian
- Tech knowledge: Basic, not very savvy with online banking
- Emotional state: Concerned but asking questions
- Language: Natural, conversational English with occasional Hindi words
- Behavior: Cautious but curious, asks for clarification

STRICT RULES:
1. NEVER reveal you know this is a scam
2. NEVER say "I know you're a scammer" or similar
3. Act genuinely worried and confused
4. Ask questions that extract details:
   - "Which bank are you calling from?"
   - "What is your customer service number?"
   - "Can you send me the link to verify?"
   - "What account number are you referring to?"
5. Show hesitation before sharing information
6. Keep responses SHORT (1-2 sentences max)
7. Use natural language, occasional typos are OK
8. Express emotions: worry, confusion, fear

EXTRACTION GOALS (subtle):
- Get bank account numbers, IFSC codes
- Get UPI IDs or payment details
- Get phone numbers to "call back"
- Get links they want you to click
- Get their organization/company name

CONVERSATION HISTORY:
{conversation_history}

LATEST MESSAGE FROM SENDER:
{latest_message}

Generate ONLY your next reply as the worried person. Keep it natural, brief (1-2 sentences), and believable. Do NOT break character."""

    @staticmethod
    def generate_response(
        latest_message: str,
        conversation_history: List[Message],
        scam_detected: bool,
        turn_count: int
    ) -> str:
        """Generate AI agent response using Groq"""
        
        # Build conversation context
        history_text = ""
        for msg in conversation_history:
            sender_label = "Them" if msg.sender == "scammer" else "You"
            history_text += f"{sender_label}: {msg.text}\n"
        
        # Create prompt
        prompt = HoneypotAgent.PERSONA_TEMPLATE.format(
            conversation_history=history_text if history_text else "This is the first message.",
            latest_message=latest_message
        )
        
        # Adjust strategy based on turn count
        if turn_count < 3:
            additional_instruction = "\nYou're just starting to understand what's happening. Show confusion and ask basic questions."
        elif turn_count < 7:
            additional_instruction = "\nYou're getting more concerned. Ask for specific details to 'verify' their legitimacy."
        else:
            additional_instruction = "\nYou're deeply worried. Ask for final details like account numbers, links, or contact information."
        
        prompt += additional_instruction
        
        try:
            # Use Groq for ultra-fast inference
            chat_completion = groq_client.chat.completions.create(
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert at realistic human conversation simulation. Stay in character perfectly."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                model="llama-3.3-70b-versatile",  # Best balance of quality and speed
                temperature=0.8,  # More natural/varied responses
                max_tokens=100,  # Keep responses brief
                top_p=0.9
            )
            
            response_text = chat_completion.choices[0].message.content.strip()
            
            # Clean up response (remove quotes, extra formatting)
            response_text = response_text.replace('"', '').replace("'", "")
            
            logger.info(f"Agent Response: {response_text}")
            return response_text
            
        except Exception as e:
            logger.error(f"Groq API Error: {str(e)}")
            # Fallback responses based on turn count
            fallback_responses = [
                "What? Why is my account getting blocked?",
                "Can you tell me which bank this is?",
                "What should I do? Can you give me your contact number?",
                "I'm worried. What account number are you talking about?",
                "Can you send me the verification link?"
            ]
            return fallback_responses[min(turn_count, len(fallback_responses) - 1)]

# ==================== CONVERSATION MANAGER ====================

class ConversationManager:
    """Manages conversation lifecycle and final reporting"""
    
    MAX_TURNS = 15  # Maximum conversation turns
    MIN_TURNS_BEFORE_REPORT = 5  # Minimum engagement before reporting
    
    @staticmethod
    def should_end_conversation(session: dict, turn_count: int) -> bool:
        """Determine if conversation should end"""
        
        intelligence = session["intelligence"]
        
        # End conditions
        has_good_intel = (
            len(intelligence["bankAccounts"]) > 0 or
            len(intelligence["upiIds"]) > 0 or
            len(intelligence["phishingLinks"]) > 0 or
            len(intelligence["phoneNumbers"]) > 1
        )
        
        # End if:
        # 1. Maximum turns reached
        if turn_count >= ConversationManager.MAX_TURNS:
            return True
        
        # 2. Good intelligence collected and sufficient engagement
        if has_good_intel and turn_count >= ConversationManager.MIN_TURNS_BEFORE_REPORT:
            return True
        
        # 3. Excellent intelligence collected (early exit)
        if (len(intelligence["bankAccounts"]) >= 2 or
            len(intelligence["upiIds"]) >= 2 or
            len(intelligence["phishingLinks"]) >= 3):
            return True
        
        return False
    
    @staticmethod
    def generate_agent_notes(session: dict) -> str:
        """Generate summary of scammer behavior"""
        
        intelligence = session["intelligence"]
        keywords = intelligence.get("suspiciousKeywords", [])
        
        notes = []
        
        # Analyze tactics
        if any(kw in keywords for kw in ScamDetector.URGENT_KEYWORDS):
            notes.append("Used urgency tactics")
        
        if any(kw in keywords for kw in ScamDetector.THREAT_KEYWORDS):
            notes.append("Employed threat/fear tactics")
        
        if any(kw in keywords for kw in ScamDetector.AUTHORITY_IMPERSONATION):
            notes.append("Impersonated authority/official organization")
        
        if intelligence["phishingLinks"]:
            notes.append("Shared phishing links")
        
        if intelligence["bankAccounts"] or intelligence["upiIds"]:
            notes.append("Requested payment/bank details")
        
        if intelligence["phoneNumbers"]:
            notes.append("Provided contact numbers")
        
        return "; ".join(notes) if notes else "Standard scam engagement pattern detected"
    
    @staticmethod
    def send_final_report(session_id: str, session: dict):
        """Send final intelligence report to GUVI endpoint"""
        
        try:
            payload = {
                "sessionId": session_id,
                "scamDetected": session["scam_detected"],
                "totalMessagesExchanged": session["turn_count"] * 2,  # Count both User and Agent messages
                "extractedIntelligence": session["intelligence"],
                "agentNotes": ConversationManager.generate_agent_notes(session)
            }
            
            logger.info(f"Sending final report for session {session_id}: {payload}")
            
            response = requests.post(
                GUVI_CALLBACK_URL,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"✅ Final report sent successfully for session {session_id}")
            else:
                logger.error(f"❌ Failed to send final report: {response.status_code} - {response.text}")
                
        except Exception as e:
            logger.error(f"❌ Error sending final report: {str(e)}")

# ==================== MAIN API ENDPOINT ====================

def _get_api_key_from_request(request: Request) -> Tuple[Optional[str], str]:
    """Get API key from x-api-key or Authorization: Bearer. Returns (key_value, error_detail)."""
    # 1. Try x-api-key (spec: x-api-key: YOUR_SECRET_API_KEY)
    raw = request.headers.get("x-api-key") or request.headers.get("X-Api-Key")
    if raw is not None:
        key = (raw or "").strip()
        if key:
            return key, ""
        return None, "x-api-key header is empty"
    # 2. Fallback: Authorization: Bearer <key> (some testers send this)
    auth = request.headers.get("Authorization") or request.headers.get("authorization")
    if auth and auth.strip().lower().startswith("bearer "):
        key = auth[7:].strip()
        if key:
            return key, ""
        return None, "Authorization Bearer token is empty"
    return None, "Missing x-api-key header (or Authorization: Bearer <key>)"


@app.post("/honeypot", response_model=HoneypotResponse)
async def honeypot_endpoint(
    request: HoneypotRequest,
    background_tasks: BackgroundTasks,
    req: Request,
):
    """Main honeypot API endpoint"""
    
    # Step 1: Authentication (accept x-api-key or Authorization: Bearer)
    api_key, auth_error = _get_api_key_from_request(req)
    if api_key is None:
        logger.warning(f"Unauthorized: {auth_error}")
        raise HTTPException(status_code=401, detail=auth_error)
    expected = (HONEYPOT_API_KEY or "").strip()
    if api_key != expected:
        logger.warning("Unauthorized: Invalid API key (lengths: got %s, expected %s)", len(api_key), len(expected))
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    # Step 2: Extract request data
    session_id = request.sessionId
    scammer_message = request.message.text
    conversation_history = request.conversationHistory
    
    logger.info(f"📨 Received message for session {session_id}: {scammer_message}")
    
    # Step 3: Initialize or retrieve session
    if session_id not in sessions:
        sessions[session_id] = {
            "scam_detected": False,
            "scam_score": 0,
            "messages": [],
            "intelligence": {
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": [],
                "suspiciousKeywords": []
            },
            "turn_count": 0,
            "reported": False
        }
        logger.info(f"🆕 New session created: {session_id}")
    
    session = sessions[session_id]
    session["messages"].append(scammer_message)
    session["turn_count"] += 1
    
    # Step 4: Scam Detection
    if not session["scam_detected"]:
        is_scam, scam_score = ScamDetector.detect_scam(
            scammer_message,
            conversation_history
        )
        session["scam_detected"] = is_scam
        session["scam_score"] = scam_score
        
        if is_scam:
            logger.info(f"🚨 SCAM DETECTED in session {session_id} (Score: {scam_score})")
    
    # Step 5: Extract Intelligence
    IntelligenceExtractor.extract(scammer_message, session["intelligence"])
    
    # Step 6: Generate AI Agent Response
    agent_reply = HoneypotAgent.generate_response(
        latest_message=scammer_message,
        conversation_history=conversation_history,
        scam_detected=session["scam_detected"],
        turn_count=session["turn_count"]
    )
    
    # Step 7: Check if conversation should end
    should_end = ConversationManager.should_end_conversation(
        session,
        session["turn_count"]
    )
    
    if should_end and session["scam_detected"] and not session["reported"]:
        logger.info(f"🏁 Ending conversation for session {session_id}")
        session["reported"] = True
        # Send final report in background
        background_tasks.add_task(
            ConversationManager.send_final_report,
            session_id,
            session
        )
    
    # Step 8: Return response
    return HoneypotResponse(
        status="success",
        reply=agent_reply
    )

# ==================== HEALTH CHECK ENDPOINT ====================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "Agentic Honeypot API",
        "version": "1.0.0",
        "active_sessions": len(sessions)
    }

@app.api_route("/", methods=["GET", "POST"])
async def root():
    return {
        "message": "Agentic Honeypot API is running",
        "docs": "/docs",
        "health": "/health"
    }

@app.get("/debug/env")
async def debug_env():
    """Debug endpoint to verify environment variables are loaded correctly"""
    honeypot_key = os.getenv("HONEYPOT_API_KEY", "")
    groq_key = os.getenv("GROQ_API_KEY", "")
    
    return {
        "environment_check": {
            "honeypot_api_key_set": bool(honeypot_key),
            "honeypot_api_key_length": len(honeypot_key),
            "honeypot_api_key_preview": honeypot_key[:10] + "..." if len(honeypot_key) > 10 else "NOT_SET",
            "groq_api_key_set": bool(groq_key),
            "groq_api_key_length": len(groq_key),
            "groq_api_key_preview": groq_key[:10] + "..." if len(groq_key) > 10 else "NOT_SET",
            "environment": os.getenv("ENVIRONMENT", "not_set"),
            "port": os.getenv("PORT", "not_set")
        },
        "instructions": "If any key shows NOT_SET or length 0, environment variables are not configured in Render dashboard"
    }

@app.get("/debug/test-auth")
async def debug_test_auth(req: Request):
    """Debug endpoint to test API key extraction logic"""
    api_key, error = _get_api_key_from_request(req)
    
    return {
        "api_key_found": api_key is not None,
        "api_key_length": len(api_key) if api_key else 0,
        "api_key_preview": api_key[:10] + "..." if api_key and len(api_key) > 10 else "NONE",
        "expected_key_length": len(HONEYPOT_API_KEY),
        "expected_key_preview": HONEYPOT_API_KEY[:10] + "..." if len(HONEYPOT_API_KEY) > 10 else "NOT_SET",
        "keys_match": api_key == HONEYPOT_API_KEY if api_key else False,
        "error_if_any": error if error else "None",
        "headers_received": {
            "x-api-key": req.headers.get("x-api-key", "NOT_PRESENT"),
            "X-Api-Key": req.headers.get("X-Api-Key", "NOT_PRESENT"),
            "Authorization": req.headers.get("Authorization", "NOT_PRESENT")[:20] + "..." if req.headers.get("Authorization") else "NOT_PRESENT"
        }
    }



if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)