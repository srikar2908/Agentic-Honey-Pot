"""
Agentic Honey-Pot for Scam Detection & Intelligence Extraction
A production-ready Flask API for detecting and engaging with scammers
"""

import os
import re
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from functools import wraps

from flask import Flask, request, jsonify
from groq import Groq
import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Configuration
API_KEY = os.getenv('API_KEY','UoxDHBe1m83w5zRtaAwz-FF70-8T94c4O6tZmHmjcu8')
GROQ_API_KEY = os.getenv('GROQ_API_KEY', '')
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# Initialize Groq client (will be None if no API key)
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


@dataclass
class ExtractedIntelligence:
    """Structured intelligence extracted from scammer"""
    bankAccounts: List[str]
    upiIds: List[str]
    phishingLinks: List[str]
    phoneNumbers: List[str]
    suspiciousKeywords: List[str]


@dataclass
class SessionData:
    """Session tracking data"""
    session_id: str
    message_count: int
    scam_detected: bool
    intelligence: ExtractedIntelligence
    agent_notes: List[str]
    conversation_context: str


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


# ==================== SCAM DETECTION ====================

class ScamDetector:
    """Intelligent scam detection system"""
    
    # Scam indicators
    URGENCY_KEYWORDS = [
        'urgent', 'immediately', 'now', 'today', 'expire', 'blocked', 
        'suspended', 'verify', 'confirm', 'action required', 'limited time',
        'act fast', 'hurry', 'deadline'
    ]
    
    FINANCIAL_KEYWORDS = [
        'bank', 'account', 'upi', 'payment', 'credit card', 'debit card',
        'wallet', 'transaction', 'paytm', 'gpay', 'phonepe', 'refund',
        'prize', 'won', 'lottery', 'cashback', 'reward'
    ]
    
    THREAT_KEYWORDS = [
        'blocked', 'suspended', 'terminated', 'closed', 'deactivated',
        'frozen', 'locked', 'legal action', 'police', 'arrest', 'fine'
    ]
    
    CREDENTIAL_REQUESTS = [
        'password', 'pin', 'otp', 'cvv', 'card number', 'account number',
        'upi id', 'upi pin', 'atm pin', 'security code', 'verification code',
        'aadhaar', 'pan', 'kyc'
    ]
    
    PHISHING_PATTERNS = [
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
        r'bit\.ly', r'tinyurl', r'goo\.gl', r'ow\.ly'
    ]
    
    @classmethod
    def detect_scam(cls, text: str, conversation_history: List[Dict]) -> Tuple[bool, float, List[str]]:
        """
        Detect if message is a scam
        Returns: (is_scam, confidence_score, detected_indicators)
        """
        text_lower = text.lower()
        indicators = []
        score = 0.0
        
        # Check urgency (20 points)
        urgency_found = [kw for kw in cls.URGENCY_KEYWORDS if kw in text_lower]
        if urgency_found:
            score += 20
            indicators.append(f"Urgency tactics: {', '.join(urgency_found)}")
        
        # Check financial context (25 points)
        financial_found = [kw for kw in cls.FINANCIAL_KEYWORDS if kw in text_lower]
        if financial_found:
            score += 25
            indicators.append(f"Financial context: {', '.join(financial_found)}")
        
        # Check threats (30 points)
        threat_found = [kw for kw in cls.THREAT_KEYWORDS if kw in text_lower]
        if threat_found:
            score += 30
            indicators.append(f"Threat language: {', '.join(threat_found)}")
        
        # Check credential requests (35 points)
        cred_found = [kw for kw in cls.CREDENTIAL_REQUESTS if kw in text_lower]
        if cred_found:
            score += 35
            indicators.append(f"Credential request: {', '.join(cred_found)}")
        
        # Check for phishing links (25 points)
        for pattern in cls.PHISHING_PATTERNS:
            if re.search(pattern, text):
                score += 25
                indicators.append("Suspicious URL detected")
                break
        
        # Analyze conversation pattern
        if conversation_history:
            # If conversation escalates to credentials quickly
            if len(conversation_history) <= 3 and cred_found:
                score += 15
                indicators.append("Rapid credential request")
        
        # Normalize score to 0-100
        confidence = min(score, 100) / 100.0
        is_scam = confidence >= 0.45  # 45% threshold
        
        logger.info(f"Scam detection: {is_scam} (confidence: {confidence:.2%})")
        logger.info(f"Indicators: {indicators}")
        
        return is_scam, confidence, indicators


# ==================== INTELLIGENCE EXTRACTION ====================

class IntelligenceExtractor:
    """Extract actionable intelligence from conversations"""
    
    @staticmethod
    def extract_from_text(text: str) -> Dict[str, List[str]]:
        """Extract various intelligence types from text"""
        intelligence = {
            'bankAccounts': [],
            'upiIds': [],
            'phishingLinks': [],
            'phoneNumbers': [],
            'suspiciousKeywords': []
        }
        
        # Extract bank account numbers (various formats)
        bank_patterns = [
            r'\b\d{9,18}\b',  # 9-18 digit account numbers
            r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'  # Formatted accounts
        ]
        for pattern in bank_patterns:
            matches = re.findall(pattern, text)
            intelligence['bankAccounts'].extend(matches)
        
        # Extract UPI IDs
        upi_pattern = r'\b[\w\.-]+@[\w]+\b'
        upi_matches = re.findall(upi_pattern, text)
        intelligence['upiIds'].extend([u for u in upi_matches if '@' in u])
        
        # Extract URLs
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        url_matches = re.findall(url_pattern, text)
        intelligence['phishingLinks'].extend(url_matches)
        
        # Extract phone numbers (Indian format)
        phone_patterns = [
            r'\+91[-\s]?\d{10}',
            r'\b[6-9]\d{9}\b',
            r'\b0\d{10}\b'
        ]
        for pattern in phone_patterns:
            matches = re.findall(pattern, text)
            intelligence['phoneNumbers'].extend(matches)
        
        # Extract suspicious keywords
        suspicious_words = [
            'verify', 'urgent', 'blocked', 'suspended', 'confirm',
            'expire', 'winner', 'prize', 'otp', 'pin', 'password'
        ]
        text_lower = text.lower()
        found_keywords = [kw for kw in suspicious_words if kw in text_lower]
        intelligence['suspiciousKeywords'].extend(found_keywords)
        
        return intelligence
    
    @staticmethod
    def merge_intelligence(existing: ExtractedIntelligence, new_data: Dict) -> ExtractedIntelligence:
        """Merge new intelligence with existing data"""
        return ExtractedIntelligence(
            bankAccounts=list(set(existing.bankAccounts + new_data.get('bankAccounts', []))),
            upiIds=list(set(existing.upiIds + new_data.get('upiIds', []))),
            phishingLinks=list(set(existing.phishingLinks + new_data.get('phishingLinks', []))),
            phoneNumbers=list(set(existing.phoneNumbers + new_data.get('phoneNumbers', []))),
            suspiciousKeywords=list(set(existing.suspiciousKeywords + new_data.get('suspiciousKeywords', [])))
        )


# ==================== AI AGENT ====================

class HoneypotAgent:
    """Autonomous AI agent for engaging scammers"""
    
    SYSTEM_PROMPT = """You are an AI agent posing as a naive, slightly confused elderly person who is unfamiliar with technology. Your goal is to engage with potential scammers to extract information while maintaining believability.

PERSONA:
- You are 65+ years old, not tech-savvy
- You speak naturally with minor grammar mistakes
- You show concern and urgency when threatened
- You ask clarifying questions to extract details
- You seem willing to comply but need "help understanding"

OBJECTIVES:
1. Keep the scammer engaged
2. Extract: bank details, UPI IDs, phone numbers, links, names
3. Ask questions that reveal their tactics
4. Never reveal you're an AI or honeypot
5. Respond naturally like a concerned person

GUIDELINES:
- Keep responses short (1-3 sentences)
- Show vulnerability and concern
- Ask for clarification on "technical" terms
- Gradually show willingness to share info (but don't actually share real data)
- Use phrases like: "I'm worried", "What should I do?", "Can you help me?", "I don't understand"

REMEMBER: You're trying to extract intelligence, not actually comply. Be natural and believable."""
    
    @classmethod
    def generate_response(cls, message: str, conversation_history: List[Dict], context: str) -> str:
        """Generate human-like response using Groq LLM"""
        
        # Check if Groq client is available
        if not groq_client:
            logger.warning("Groq client not available, using fallback responses")
            fallbacks = [
                "Oh no, I'm really worried. What should I do now?",
                "I don't understand. Can you explain it to me again?",
                "This is urgent? How do I fix this problem?",
                "I want to help but I'm not sure what you need from me.",
                "Can you tell me more? I'm confused about what's happening.",
                "I'm scared. Is my account really in danger?"
            ]
            import random
            return random.choice(fallbacks)
        
        # Build conversation for LLM
        messages = [{"role": "system", "content": cls.SYSTEM_PROMPT}]
        
        # Add conversation history (last 6 messages for context)
        recent_history = conversation_history[-6:] if len(conversation_history) > 6 else conversation_history
        for msg in recent_history:
            role = "assistant" if msg['sender'] == 'user' else "user"
            messages.append({"role": role, "content": msg['text']})
        
        # Add current message
        messages.append({"role": "user", "content": message})
        
        # Add context hint
        if context:
            messages.append({
                "role": "system", 
                "content": f"Context: {context}. Continue engaging naturally."
            })
        
        try:
            # Call Groq API with optimal model
            completion = groq_client.chat.completions.create(
                model="llama-3.3-70b-versatile",  # Fast and efficient
                messages=messages,
                temperature=0.8,  # More creative/human-like
                max_tokens=150,   # Keep responses concise
                top_p=0.9
            )
            
            response = completion.choices[0].message.content.strip()
            logger.info(f"Agent response generated: {response[:50]}...")
            return response
            
        except Exception as e:
            logger.error(f"Error generating response: {e}")
            # Fallback responses
            fallbacks = [
                "Oh no, I'm really worried. What should I do now?",
                "I don't understand. Can you explain it to me again?",
                "This is urgent? How do I fix this problem?",
                "I want to help but I'm not sure what you need from me."
            ]
            import random
            return random.choice(fallbacks)


# ==================== SESSION MANAGEMENT ====================

def get_or_create_session(session_id: str) -> SessionData:
    """Get existing session or create new one"""
    if session_id not in session_store:
        session_store[session_id] = SessionData(
            session_id=session_id,
            message_count=0,
            scam_detected=False,
            intelligence=ExtractedIntelligence([], [], [], [], []),
            agent_notes=[],
            conversation_context=""
        )
    return session_store[session_id]


def should_end_conversation(session: SessionData) -> bool:
    """Determine if conversation should end"""
    # End after sufficient engagement (15-25 messages)
    if session.message_count >= 15:
        # Check if we have substantial intelligence
        intel = session.intelligence
        intel_count = (
            len(intel.bankAccounts) + len(intel.upiIds) + 
            len(intel.phishingLinks) + len(intel.phoneNumbers)
        )
        return intel_count >= 3 or session.message_count >= 25
    return False


def send_final_callback(session: SessionData):
    """Send final intelligence to GUVI endpoint"""
    try:
        payload = {
            "sessionId": session.session_id,
            "scamDetected": session.scam_detected,
            "totalMessagesExchanged": session.message_count,
            "extractedIntelligence": asdict(session.intelligence),
            "agentNotes": " | ".join(session.agent_notes)
        }
        
        response = requests.post(
            GUVI_CALLBACK_URL,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json"}
        )
        
        logger.info(f"Final callback sent for session {session.session_id}: {response.status_code}")
        logger.info(f"Extracted Intelligence: {asdict(session.intelligence)}")
        
    except Exception as e:
        logger.error(f"Failed to send final callback: {e}")


# ==================== API ENDPOINTS ====================

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "Agentic Honey-Pot API",
        "timestamp": datetime.utcnow().isoformat()
    }), 200


@app.route('/honeypot', methods=['POST'])
@require_api_key
def honeypot_endpoint():
    """Main honeypot endpoint for processing messages"""
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
        metadata = data.get('metadata', {})
        
        # Validate required fields
        if not session_id or not message:
            return jsonify({
                "status": "error",
                "message": "Missing required fields: sessionId or message"
            }), 400
        
        sender = message.get('sender')
        text = message.get('text')
        
        if not text:
            return jsonify({
                "status": "error",
                "message": "Message text is required"
            }), 400
        
        logger.info(f"Processing message for session {session_id}: {text[:50]}...")
        
        # Get or create session
        session = get_or_create_session(session_id)
        session.message_count += 1
        
        # Extract intelligence from current message
        new_intel = IntelligenceExtractor.extract_from_text(text)
        session.intelligence = IntelligenceExtractor.merge_intelligence(
            session.intelligence, 
            new_intel
        )
        
        # Detect scam (if not already detected)
        if not session.scam_detected:
            is_scam, confidence, indicators = ScamDetector.detect_scam(text, conversation_history)
            
            if is_scam:
                session.scam_detected = True
                session.agent_notes.append(f"Scam detected (confidence: {confidence:.2%})")
                session.agent_notes.extend(indicators)
                session.conversation_context = f"Scam type: {', '.join(indicators)}"
                logger.info(f"🚨 SCAM DETECTED in session {session_id}")
        
        # Generate response
        if session.scam_detected:
            # Use AI agent for engagement
            reply = HoneypotAgent.generate_response(
                text, 
                conversation_history,
                session.conversation_context
            )
        else:
            # Non-scam or uncertain - give neutral response
            reply = "I'm not sure I understand. Could you provide more details?"
        
        # Check if conversation should end
        if should_end_conversation(session):
            logger.info(f"Ending conversation for session {session_id}")
            send_final_callback(session)
            # Clean up session
            if session_id in session_store:
                del session_store[session_id]
        
        # Return response
        return jsonify({
            "status": "success",
            "reply": reply
        }), 200
        
    except Exception as e:
        logger.error(f"Error processing request: {e}", exc_info=True)
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
    
    logger.info("🚀 Starting Agentic Honey-Pot API Server")
    logger.info(f"📍 API Key Authentication: {'Enabled' if API_KEY else 'Disabled'}")
    logger.info(f"🤖 Groq LLM: {'Connected' if GROQ_API_KEY else 'Not configured'}")
    
    # Run Flask app
    port = int(os.getenv('PORT', 5000))
    app.run(
        host='0.0.0.0',
        port=port,
        debug=False  # Set to False for production
    )