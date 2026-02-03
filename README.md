# 🍯 Agentic Honey-Pot for Scam Detection

An intelligent AI-powered honeypot system that detects scam messages and autonomously engages scammers to extract actionable intelligence.

## 🎯 Features

- **Intelligent Scam Detection**: Multi-factor analysis with 45%+ confidence threshold
- **Autonomous AI Agent**: Uses Groq's LLaMA 3.3 70B model for human-like engagement
- **Intelligence Extraction**: Automatically extracts bank accounts, UPI IDs, phone numbers, URLs
- **Multi-turn Conversations**: Maintains context across entire conversation lifecycle
- **Production-Ready**: Includes authentication, logging, error handling, and monitoring
- **Optimized Performance**: Minimal token usage with efficient prompt templates

## 🏗️ Architecture

```
┌─────────────┐
│   Request   │
│  (w/ auth)  │
└──────┬──────┘
       │
       ▼
┌─────────────────┐
│ Scam Detection  │ ◄── Rule-based + Pattern matching
└────────┬────────┘
         │
         ▼ (if scam detected)
┌─────────────────┐
│   AI Agent      │ ◄── Groq LLaMA 3.3 70B
│  (Engagement)   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Intelligence   │ ◄── Regex extraction
│   Extraction    │
└────────┬────────┘
         │
         ▼ (after 15-25 messages)
┌─────────────────┐
│ Final Callback  │ ◄── Send to GUVI endpoint
└─────────────────┘
```

## 🚀 Quick Start

### 1. Clone or Download Files

Ensure you have these files:
- `main.py` - Main Flask application
- `requirements.txt` - Python dependencies
- `.env.example` - Environment variable template
- `Procfile` - Render deployment config
- `render.yaml` - Render service configuration

### 2. Set Up Environment Variables

Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

Edit `.env` and add your keys:
```env
API_KEY=your-super-secret-api-key-12345
GROQ_API_KEY=gsk_your_groq_api_key_here
PORT=5000
```

**Get Groq API Key:**
1. Go to https://console.groq.com
2. Sign up/Login
3. Navigate to API Keys
4. Create a new API key
5. Copy and paste into `.env`

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run Locally

```bash
python main.py
```

The server will start on `http://localhost:5000`

## 🌐 Deploy to Render

### Method 1: Using Render Dashboard

1. **Create Account**: Go to https://render.com and sign up

2. **New Web Service**:
   - Click "New +" → "Web Service"
   - Connect your GitHub repo (or use manual deploy)

3. **Configure Service**:
   - **Name**: `agentic-honeypot`
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn main:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120`

4. **Add Environment Variables**:
   - Go to "Environment" tab
   - Add:
     - `API_KEY`: Your secret API key
     - `GROQ_API_KEY`: Your Groq API key
     - `PYTHON_VERSION`: `3.11.0`

5. **Deploy**: Click "Create Web Service"

### Method 2: Using render.yaml (Auto-deploy)

1. Push code to GitHub with `render.yaml` included
2. In Render dashboard: "New +" → "Blueprint"
3. Connect repository
4. Render will auto-detect `render.yaml` and deploy

**Your API will be available at**: `https://your-service-name.onrender.com`

## 📡 API Endpoints

### 1. Health Check
```bash
GET /health
```

Response:
```json
{
  "status": "healthy",
  "service": "Agentic Honey-Pot API",
  "timestamp": "2024-01-01T12:00:00.000000"
}
```

### 2. Main Honeypot Endpoint
```bash
POST /honeypot
```

**Headers:**
```
x-api-key: your-secret-api-key-here
Content-Type: application/json
```

**Request Body:**
```json
{
  "sessionId": "abc123-session-id",
  "message": {
    "sender": "scammer",
    "text": "Your bank account will be blocked. Verify now!",
    "timestamp": 1770005528731
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "reply": "Oh no! Why will my account be blocked? I'm very worried."
}
```

### 3. Test Endpoint
```bash
POST /test
```

**Headers:** Same as above

**Response:**
```json
{
  "status": "success",
  "message": "Honeypot API is working correctly",
  "endpoint": "operational",
  "authentication": "verified"
}
```

## 🧪 Testing

### Using cURL

```bash
# Health check
curl https://your-app.onrender.com/health

# Test endpoint
curl -X POST https://your-app.onrender.com/test \
  -H "x-api-key: your-secret-api-key-here" \
  -H "Content-Type: application/json"

# Honeypot endpoint
curl -X POST https://your-app.onrender.com/honeypot \
  -H "x-api-key: your-secret-api-key-here" \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "test-123",
    "message": {
      "sender": "scammer",
      "text": "Your account will be blocked. Share OTP now!",
      "timestamp": 1770005528731
    },
    "conversationHistory": [],
    "metadata": {
      "channel": "SMS",
      "language": "English",
      "locale": "IN"
    }
  }'
```

### Using Python

```python
import requests

url = "https://your-app.onrender.com/honeypot"
headers = {
    "x-api-key": "your-secret-api-key-here",
    "Content-Type": "application/json"
}
payload = {
    "sessionId": "test-session-123",
    "message": {
        "sender": "scammer",
        "text": "Urgent! Your bank account needs verification.",
        "timestamp": 1770005528731
    },
    "conversationHistory": [],
    "metadata": {
        "channel": "SMS",
        "language": "English",
        "locale": "IN"
    }
}

response = requests.post(url, json=payload, headers=headers)
print(response.json())
```

## 🔍 How It Works

### Scam Detection Algorithm

The system uses multi-factor analysis:

1. **Urgency Detection** (20 points): Keywords like "urgent", "immediately", "now"
2. **Financial Context** (25 points): "bank", "UPI", "payment", "card"
3. **Threat Language** (30 points): "blocked", "suspended", "legal action"
4. **Credential Requests** (35 points): "OTP", "PIN", "password", "CVV"
5. **Phishing Links** (25 points): Suspicious URLs detected

**Threshold**: 45% confidence = Scam detected

### AI Agent Persona

The agent poses as a **65+ year old, tech-naive person** who:
- Shows concern and vulnerability
- Asks clarifying questions
- Appears willing to help but needs guidance
- Makes minor grammar mistakes
- Never reveals it's an AI

### Intelligence Extraction

Automatically extracts:
- **Bank Accounts**: 9-18 digit numbers
- **UPI IDs**: Format `username@bank`
- **Phone Numbers**: Indian formats (+91, 10-digit)
- **URLs**: Any HTTP/HTTPS links
- **Keywords**: Suspicious terms used

### Conversation Lifecycle

1. **Initial Detection**: First message analyzed for scam patterns
2. **Engagement**: AI agent responds naturally (15-25 messages)
3. **Intelligence Gathering**: Continuous extraction throughout conversation
4. **Termination**: After sufficient engagement, final callback sent
5. **Reporting**: Intelligence sent to GUVI evaluation endpoint

## 📊 Final Callback

After conversation ends, the system automatically sends:

```json
{
  "sessionId": "abc123-session-id",
  "scamDetected": true,
  "totalMessagesExchanged": 18,
  "extractedIntelligence": {
    "bankAccounts": ["123456789012"],
    "upiIds": ["scammer@paytm"],
    "phishingLinks": ["http://fake-bank.com"],
    "phoneNumbers": ["+919876543210"],
    "suspiciousKeywords": ["urgent", "blocked", "verify", "otp"]
  },
  "agentNotes": "Scam detected | Threat language | Credential request"
}
```

Sent to: `https://hackathon.guvi.in/api/updateHoneyPotFinalResult`

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `API_KEY` | Authentication key for your API | Yes |
| `GROQ_API_KEY` | Groq API key for LLM access | Yes |
| `PORT` | Port number (auto-set by Render) | No (default: 5000) |

### Tuning Parameters

In `main.py`, you can adjust:

```python
# Scam detection threshold (line ~185)
is_scam = confidence >= 0.45  # 45% threshold

# Conversation length (line ~397)
if session.message_count >= 15:  # Min 15 messages
    return intel_count >= 3 or session.message_count >= 25  # Max 25

# LLM parameters (line ~360)
temperature=0.8,  # Creativity (0.7-0.9)
max_tokens=150,   # Response length (100-200)
top_p=0.9         # Diversity (0.85-0.95)
```

## 🛡️ Security Features

- ✅ API Key authentication on all endpoints
- ✅ Request validation and sanitization
- ✅ Rate limiting ready (can integrate Redis)
- ✅ Comprehensive error handling
- ✅ Secure header handling
- ✅ No sensitive data in logs

## 📝 Logging

All important events are logged:
- Incoming requests
- Scam detection results
- Intelligence extraction
- Agent responses
- Final callbacks
- Errors and warnings

View logs in Render dashboard: Your Service → Logs

## 🔧 Troubleshooting

### Issue: API returns 401 Unauthorized
**Solution**: Check that `x-api-key` header matches your `API_KEY` environment variable

### Issue: Agent not responding
**Solution**: Verify `GROQ_API_KEY` is correctly set and valid

### Issue: Slow responses
**Solution**: 
- Check Groq API quota
- Reduce `max_tokens` parameter
- Use fewer conversation history messages

### Issue: Missing intelligence
**Solution**: Conversation may be too short. Adjust termination threshold.

## 📈 Performance Optimization

### Token Usage
- System prompt: ~250 tokens
- History (6 messages): ~200 tokens
- Response generation: ~150 tokens
- **Total per call**: ~600 tokens (very efficient!)

### Response Time
- Scam detection: <50ms
- Intelligence extraction: <100ms
- AI response generation: 1-3 seconds
- **Total**: ~2-4 seconds per message

## 🎓 Advanced Usage

### Custom Scam Patterns

Add custom keywords in `ScamDetector` class:

```python
CUSTOM_KEYWORDS = [
    'your_keyword_1', 
    'your_keyword_2'
]
```

### Modify Agent Persona

Edit `SYSTEM_PROMPT` in `HoneypotAgent` class to change behavior.

### Change LLM Model

In `generate_response()` method:

```python
model="llama-3.3-70b-versatile"  # Fast
# or
model="llama-3.1-70b-versatile"  # Alternative
```

## 📞 Support

For issues or questions:
1. Check logs in Render dashboard
2. Review this README
3. Test with `/test` endpoint first
4. Verify environment variables

## 🏆 Evaluation Checklist

✅ API deployed and accessible
✅ Authentication working (`x-api-key`)
✅ Scam detection functional
✅ AI agent engaging naturally
✅ Intelligence extraction working
✅ Multi-turn conversations supported
✅ Final callback sending correctly
✅ Error handling implemented
✅ Logging comprehensive
✅ Response format correct

## 📄 License

This project is created for the GUVI Hackathon.

---

**Built with ❤️ using Flask, Groq, and AI**

🚀 **Ready for deployment!** 🚀