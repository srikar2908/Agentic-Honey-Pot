"""
Agentic Honey-Pot for Scam Detection & Intelligence Extraction
Optimized version with single LLM call and improved pattern extraction
"""

import os
import re
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict, field
from functools import wraps

from flask import Flask, request, jsonify, make_response
from groq import Groq
import requests

# Load environment variables from .env file (for local development)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, will use system env vars

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Configuration
API_KEY = os.getenv('API_KEY', 'UoxDHBe1m83w5zRtaAwz-FF70-8T94c4O6tZmHmjcu8')
GROQ_API_KEY = os.getenv('GROQ_API_KEY', '')
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# Initialize Groq client
groq_client = None
if GROQ_API_KEY:
    try:
        groq_client = Groq(api_key=GROQ_API_KEY)
        logger.info("✅ Groq client initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize Groq client: {e}")
        groq_client = None
else:
    logger.warning("⚠️  GROQ_API_KEY not set! Agent responses will use fallback mode.")

# Session storage (in production, use Redis or database)
session_store = {}


# ==================== CORS CONFIGURATION ====================

@app.after_request
def add_cors_headers(response):
    """Add CORS headers to all responses"""
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, PUT, DELETE'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, x-api-key, Authorization'
    response.headers['Access-Control-Max-Age'] = '3600'
    return response


@dataclass
class ExtractedIntelligence:
    """Structured intelligence extracted from scammer"""
    bankAccounts: List[str] = field(default_factory=list)
    upiIds: List[str] = field(default_factory=list)
    phishingLinks: List[str] = field(default_factory=list)
    phoneNumbers: List[str] = field(default_factory=list)
    suspiciousKeywords: List[str] = field(default_factory=list)


@dataclass
class SessionData:
    """Session tracking data"""
    session_id: str
    message_count: int = 0
    scam_detected: bool = False
    intelligence: ExtractedIntelligence = field(default_factory=lambda: ExtractedIntelligence())
    agent_notes: List[str] = field(default_factory=list)
    conversation_context: str = ""
    risk_score: float = 0.0  # Cumulative risk score for multi-turn detection


# ==================== AUTHENTICATION ====================

def require_api_key(f):
    """Decorator for API key authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('x-api-key')
        if not api_key or api_key != API_KEY:
            logger.warning(f"Unauthorized access attempt from {request.remote_addr}")
            return jsonify({
                "status": "error",
                "message": "Unauthorized. Invalid or missing API key."
            }), 401
        return f(*args, **kwargs)
    return decorated_function


# ==================== PATTERN EXTRACTION (LAYER 1: REGEX) ====================

class PatternExtractor:
    """Extract intelligence patterns using regex"""
    
    @staticmethod
    def extract_phone_numbers(text: str) -> List[str]:
        """Extract Indian phone numbers"""
        patterns = [
            r'\+91[\s-]?\d{10}',  # +91 format
            r'\b[6-9]\d{9}\b'      # 10 digit starting with 6-9
        ]
        phones = []
        for pattern in patterns:
            phones.extend(re.findall(pattern, text))
        return list(set(phones))
    
    @staticmethod
    def extract_upi_ids(text: str) -> List[str]:
        """Extract UPI IDs"""
        # UPI format: name@bank (avoid matching emails with common domains)
        upi_pattern = r'\b[\w.-]{2,}@(?:upi|paytm|ybl|okaxis|okicici|okhdfcbank|axl|ibl|oksbi)\b'
        upis = re.findall(upi_pattern, text, re.IGNORECASE)
        return list(set(upis))
    
    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """Extract URLs/phishing links"""
        url_pattern = r'https?://[^\s]+'
        urls = re.findall(url_pattern, text)
        return list(set(urls))
    
    @staticmethod
    def extract_bank_accounts(text: str) -> List[str]:
        """Extract bank account numbers (9-18 digits)"""
        # Avoid extracting phone numbers as bank accounts
        account_pattern = r'\b\d{12,18}\b'
        accounts = re.findall(account_pattern, text)
        return list(set(accounts))
    
    @staticmethod
    def extract_keywords(text: str) -> List[str]:
        """Extract suspicious keywords"""
        keywords = [
            'urgent', 'immediately', 'verify', 'blocked', 'suspended',
            'account', 'payment', 'upi', 'otp', 'pin', 'expire',
            'click', 'link', 'confirm', 'prize', 'winner', 'refund'
        ]
        text_lower = text.lower()
        found = [kw for kw in keywords if kw in text_lower]
        return list(set(found))
    
    @classmethod
    def extract_all(cls, text: str) -> Dict[str, List[str]]:
        """Extract all intelligence from text"""
        return {
            'phoneNumbers': cls.extract_phone_numbers(text),
            'upiIds': cls.extract_upi_ids(text),
            'phishingLinks': cls.extract_urls(text),
            'bankAccounts': cls.extract_bank_accounts(text),
            'suspiciousKeywords': cls.extract_keywords(text)
        }


# ==================== LIGHT RULE-BASED FILTER ====================

class QuickFilter:
    """Fast preliminary scam check before LLM"""
    
    # Critical scam indicators (enhanced)
    SCAM_SIGNALS = [
        'blocked', 'suspended', 'verify', 'otp', 'pin', 'urgent',
        'immediately', 'expire', 'upi', 'account', 'payment', 'confirm',
        'bank', 'rbi', 'customer care', 'support team'  # Added more signals
    ]
    
    @classmethod
    def is_likely_scam(cls, text: str) -> bool:
        """Quick check if message has scam indicators"""
        text_lower = text.lower()
        
        # Check for scam signals
        signal_count = sum(1 for signal in cls.SCAM_SIGNALS if signal in text_lower)
        
        # Check for URLs
        has_url = bool(re.search(r'https?://', text))
        
        # Check for phone numbers
        has_phone = bool(re.search(r'\+91[\s-]?\d{10}|\b[6-9]\d{9}\b', text))
        
        # Quick scam likelihood
        is_likely = signal_count >= 2 or (signal_count >= 1 and (has_url or has_phone))
        
        return is_likely


# ==================== AI AGENT WITH UNIFIED LLM CALL ====================

class UnifiedAgent:
    """Single LLM call for detection + response + extraction"""
    
    # Ultra-compact prompt (further reduced tokens)
    SYSTEM_PROMPT = """AI honeypot as elderly person (65+), tech-naive.

GOALS: Engage scammer, extract intel (bank/UPI/phone/links), stay hidden.
BEHAVIOR: Worried, confused, ask details, seem willing but need help.
STYLE: 1-3 sentences, pure English.

Examples: "I'm worried, what should I do?", "Which bank?", "Can you explain?"""
    
    @classmethod
    def process_message(cls, text: str, conversation_history: List[Dict], regex_intel: Dict) -> Tuple[bool, str, Dict]:
        """
        Single LLM call for:
        1. Scam detection
        2. Agent response
        3. Intelligence extraction (advanced)
        
        Returns: (is_scam, agent_reply, llm_extracted_intel)
        """
        
        if not groq_client:
            logger.warning("⚠️ Groq client not available, using fallback")
            logger.warning("⚠️ Please set GROQ_API_KEY environment variable for LLM responses")
            return cls._fallback_process(text, regex_intel)
        
        # Build compact conversation context
        messages = [{"role": "system", "content": cls.SYSTEM_PROMPT}]
        
        # Add recent history (last 4 messages only to save tokens)
        recent = conversation_history[-4:] if len(conversation_history) > 4 else conversation_history
        for msg in recent:
            role = "assistant" if msg['sender'] == 'user' else "user"
            messages.append({"role": role, "content": msg['text']})
        
        # Add current message
        messages.append({"role": "user", "content": text})
        
        # Compact unified instruction (reduced tokens)
        instruction = f"""Analyze and return JSON with keys:
is_scam (bool), confidence (0-1), reply (elderly persona, 1-3 sentences), 
intelligence (bankAccounts, upiIds, phishingLinks, phoneNumbers, suspiciousKeywords as arrays), 
scam_notes (brief reason).

Already detected via regex: {json.dumps(regex_intel)}
Extract ADDITIONAL intelligence. Return ONLY valid JSON."""
        
        # Add as user message (NOT system) for better response consistency
        messages.append({"role": "user", "content": instruction})
        
        try:
            logger.info("🤖 Calling LLM for analysis...")
            completion = groq_client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=messages,
                temperature=0.7,
                max_tokens=300,
                response_format={"type": "json_object"}
            )
            
            response_text = completion.choices[0].message.content.strip()
            logger.info(f"📥 LLM raw response: {response_text[:100]}...")
            
            result = json.loads(response_text)
            
            is_scam = result.get('is_scam', False)
            agent_reply = result.get('reply', "I'm not sure I understand.")
            llm_intel = result.get('intelligence', {})
            
            logger.info(f"✅ LLM Response: is_scam={is_scam}, reply={agent_reply[:50]}...")
            
            return is_scam, agent_reply, llm_intel
            
        except json.JSONDecodeError as e:
            logger.error(f"❌ JSON parsing error: {e}")
            logger.error(f"Raw response was: {response_text if 'response_text' in locals() else 'N/A'}")
            return cls._fallback_process(text, regex_intel)
        except Exception as e:
            logger.error(f"❌ LLM processing error: {type(e).__name__}: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return cls._fallback_process(text, regex_intel)
    
    @classmethod
    def _fallback_process(cls, text: str, regex_intel: Dict) -> Tuple[bool, str, Dict]:
        """Fallback when LLM is unavailable"""
        import random
        
        logger.warning("⚠️ Using FALLBACK responses (LLM unavailable)")
        
        # Simple heuristic scam detection
        text_lower = text.lower()
        scam_words = ['urgent', 'blocked', 'verify', 'otp', 'suspend', 'expire']
        is_scam = sum(1 for word in scam_words if word in text_lower) >= 2
        
        # More varied fallback responses matching elderly persona
        fallbacks = [
            "Oh my, this sounds serious. What exactly happened to my account?",
            "I'm very worried now. Can you tell me what I need to do?",
            "I don't really understand these technical things. Could you explain it simply?",
            "My son usually helps me with the bank. Is this very urgent?",
            "I'm scared. Is my money safe? What should I do to fix this?",
            "Sorry, I'm not good with computers. Can you help me step by step?",
            "Oh dear, I didn't know there was a problem. How do I verify this?",
            "This is confusing for me. Which bank are you calling from?",
            "I'm an old person, please be patient. What information do you need?",
            "My daughter handles these things usually. Is it very urgent that I do it now?"
        ]
        reply = random.choice(fallbacks)
        
        return is_scam, reply, {}


# ==================== INTELLIGENCE MERGER ====================

class IntelligenceMerger:
    """Merge regex + LLM intelligence"""
    
    @staticmethod
    def merge(regex_intel: Dict, llm_intel: Dict, existing: ExtractedIntelligence) -> ExtractedIntelligence:
        """Combine all intelligence sources and deduplicate"""
        
        def combine_lists(*lists):
            combined = []
            for lst in lists:
                if lst:
                    combined.extend(lst)
            return list(set(combined))  # Deduplicate
        
        return ExtractedIntelligence(
            bankAccounts=combine_lists(
                existing.bankAccounts,
                regex_intel.get('bankAccounts', []),
                llm_intel.get('bankAccounts', [])
            ),
            upiIds=combine_lists(
                existing.upiIds,
                regex_intel.get('upiIds', []),
                llm_intel.get('upiIds', [])
            ),
            phishingLinks=combine_lists(
                existing.phishingLinks,
                regex_intel.get('phishingLinks', []),
                llm_intel.get('phishingLinks', [])
            ),
            phoneNumbers=combine_lists(
                existing.phoneNumbers,
                regex_intel.get('phoneNumbers', []),
                llm_intel.get('phoneNumbers', [])
            ),
            suspiciousKeywords=combine_lists(
                existing.suspiciousKeywords,
                regex_intel.get('suspiciousKeywords', []),
                llm_intel.get('suspiciousKeywords', [])
            )
        )


# ==================== SESSION MANAGEMENT ====================

def get_or_create_session(session_id: str) -> SessionData:
    """Get existing session or create new one"""
    if session_id not in session_store:
        session_store[session_id] = SessionData(
            session_id=session_id,
            message_count=0,
            scam_detected=False,
            intelligence=ExtractedIntelligence(),
            agent_notes=[],
            conversation_context=""
        )
    return session_store[session_id]


def should_end_conversation(session: SessionData) -> bool:
    """Determine if conversation should end"""
    # End after sufficient engagement (15-25 messages)
    if session.message_count >= 15:
        intel = session.intelligence
        intel_count = (
            len(intel.bankAccounts) + len(intel.upiIds) + 
            len(intel.phishingLinks) + len(intel.phoneNumbers)
        )
        return intel_count >= 3 or session.message_count >= 25
    return False


def send_final_callback(session: SessionData):
    """Send final intelligence to GUVI endpoint with retry logic"""
    payload = {
        "sessionId": session.session_id,
        "scamDetected": session.scam_detected,
        "totalMessagesExchanged": session.message_count,
        "extractedIntelligence": asdict(session.intelligence),
        "agentNotes": " | ".join(session.agent_notes)
    }
    
    # Retry logic for reliability (critical for scoring)
    for attempt in range(3):
        try:
            response = requests.post(
                GUVI_CALLBACK_URL,
                json=payload,
                timeout=10,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                logger.info(f"✅ Final callback sent for session {session.session_id} (attempt {attempt+1})")
                logger.info(f"📊 Extracted Intelligence: {asdict(session.intelligence)}")
                break
            else:
                logger.warning(f"⚠️  Callback attempt {attempt+1} returned status {response.status_code}")
                
        except Exception as e:
            logger.warning(f"⚠️  Callback attempt {attempt+1} failed: {e}")
            if attempt == 2:  # Last attempt
                logger.error(f"❌ All callback attempts failed for session {session.session_id}")


# ==================== API ENDPOINTS ====================

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "Agentic Honey-Pot API",
        "timestamp": datetime.utcnow().isoformat()
    }), 200


@app.route('/honeypot', methods=['GET', 'POST', 'OPTIONS'])
def honeypot_endpoint():
    """Main honeypot endpoint - Optimized flow"""
    
    # Handle OPTIONS preflight request
    if request.method == 'OPTIONS':
        return make_response('', 204)
    
    # Handle GET request
    if request.method == 'GET':
        return jsonify({
            "status": "success",
            "message": "Honeypot API is operational",
            "endpoints": {
                "POST /honeypot": "Submit messages for scam detection",
                "GET /honeypot": "Check API status",
                "GET /health": "Health check"
            }
        }), 200
    
    # Handle POST request - requires API key
    api_key = request.headers.get('x-api-key')
    if not api_key or api_key != API_KEY:
        logger.warning(f"Unauthorized access attempt from {request.remote_addr}")
        return jsonify({
            "status": "error",
            "message": "Unauthorized. Invalid or missing API key."
        }), 401
    
    try:
        # Parse request
        data = request.get_json()
        
        if not data:
            return jsonify({
                "status": "error",
                "message": "Invalid JSON payload"
            }), 400
        
        # Extract request data
        session_id = data.get('sessionId')
        message = data.get('message', {})
        conversation_history = data.get('conversationHistory', [])
        
        # Validate required fields
        if not session_id or not message:
            return jsonify({
                "status": "error",
                "message": "Missing required fields: sessionId or message"
            }), 400
        
        text = message.get('text')
        if not text:
            return jsonify({
                "status": "error",
                "message": "Message text is required"
            }), 400
        
        logger.info(f"📨 Processing session={session_id}, msg={text[:50]}...")
        
        # Get or create session
        session = get_or_create_session(session_id)
        session.message_count += 1
        
        # ===== OPTIMIZED FLOW =====
        # Step 1: Light rule-based filter
        likely_scam = QuickFilter.is_likely_scam(text)
        
        # IMPORTANT: Always allow first 2 messages to reach LLM for better early detection
        if session.message_count <= 2:
            likely_scam = True
            logger.info("🔍 First messages always processed by LLM")
        
        if not likely_scam and not session.scam_detected:
            # Not likely scam, use simple response
            logger.info("⚪ Quick filter: Not likely scam")
            reply = "I'm not sure I understand. Could you provide more details?"
            
            return jsonify({
                "status": "success",
                "reply": reply
            }), 200
        
        # Step 2: Regex extraction (fast, always run)
        regex_intel = PatternExtractor.extract_all(text)
        
        # Step 3: Single LLM call (detection + reply + extraction)
        is_scam, agent_reply, llm_intel = UnifiedAgent.process_message(
            text, 
            conversation_history,
            regex_intel
        )
        
        # Step 4: Update session with risk scoring
        if is_scam:
            confidence = llm_intel.get('confidence', 0.7)  # Default if not provided
            session.risk_score += confidence
            
            # Multi-turn detection: mark as scam if cumulative risk is high
            if session.risk_score > 1.5 and not session.scam_detected:
                session.scam_detected = True
                session.agent_notes.append(f"Scam detected at message {session.message_count} (risk_score: {session.risk_score:.2f})")
                logger.info(f"🚨 SCAM DETECTED in session {session_id} (cumulative risk: {session.risk_score:.2f})")
            elif is_scam and not session.scam_detected:
                session.scam_detected = True
                session.agent_notes.append(f"Scam detected at message {session.message_count}")
                logger.info(f"🚨 SCAM DETECTED in session {session_id}")
        
        # Step 5: Merge intelligence (regex + LLM)
        session.intelligence = IntelligenceMerger.merge(
            regex_intel,
            llm_intel,
            session.intelligence
        )
        
        # Step 6: Check if conversation should end
        if should_end_conversation(session):
            logger.info(f"🏁 Ending conversation for session {session_id}")
            send_final_callback(session)
            # Clean up session
            if session_id in session_store:
                del session_store[session_id]
        
        # Return response
        return jsonify({
            "status": "success",
            "reply": agent_reply
        }), 200
        
    except Exception as e:
        logger.error(f"❌ Error processing request: {e}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": "Internal server error"
        }), 500


@app.route('/test', methods=['POST'])
@require_api_key
def test_endpoint():
    """Test endpoint for validation"""
    return jsonify({
        "status": "success",
        "message": "Honeypot API is working correctly",
        "endpoint": "operational",
        "authentication": "verified"
    }), 200


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        "status": "error",
        "message": "Endpoint not found"
    }), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {error}")
    return jsonify({
        "status": "error",
        "message": "Internal server error"
    }), 500


# ==================== MAIN ====================

if __name__ == '__main__':
    # Validate environment variables
    if not GROQ_API_KEY:
        logger.warning("⚠️  GROQ_API_KEY not set! Please set it in environment variables.")
    
    logger.info("🚀 Starting Agentic Honey-Pot API Server (Optimized)")
    logger.info(f"📍 API Key Authentication: {'Enabled' if API_KEY else 'Disabled'}")
    logger.info(f"🤖 Groq LLM: {'Connected' if GROQ_API_KEY else 'Not configured'}")
    logger.info(f"⚡ Features: Single LLM Call | Regex+LLM Hybrid | Quick Filter")
    
    # Run Flask app
    port = int(os.getenv('PORT', 5000))
    app.run(
        host='0.0.0.0',
        port=port,
        debug=False
    )