const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const Telnyx = require('telnyx');
const fs = require('fs');
const path = require('path');

const telnyx = Telnyx(process.env.TELNYX_API_KEY);

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Configuration
const OWNER_PHONE_NUMBER = process.env.OWNER_PHONE_NUMBER || '+18324254469';
const SHIELD_PHONE_NUMBER = process.env.SHIELD_PHONE_NUMBER || '+13466036303';
const BASE_URL = process.env.RENDER_EXTERNAL_URL || 'https://mobile-call-shield.onrender.com';

// Local JSON file to store settings and contacts
const PASSPHRASE_FILE = path.join(__dirname, 'passphrases.json');

// -------------------------------------------------------------
// Data Helper Functions (Structured JSON Model)
// -------------------------------------------------------------
function loadData() {
  try {
    if (fs.existsSync(PASSPHRASE_FILE)) {
      const raw = fs.readFileSync(PASSPHRASE_FILE, 'utf8');
      const parsed = JSON.parse(raw);
      return {
        settings: parsed.settings || { ownerPhoneNumber: OWNER_PHONE_NUMBER, alertsEnabled: true },
        contacts: parsed.contacts || parsed.passphrases || {}
      };
    }
  } catch (err) {
    console.error('[STORAGE] Error reading JSON data:', err.message);
  }
  return {
    settings: { ownerPhoneNumber: OWNER_PHONE_NUMBER, alertsEnabled: true },
    contacts: {}
  };
}

function saveData(data) {
  try {
    fs.writeFileSync(PASSPHRASE_FILE, JSON.stringify(data, null, 2), 'utf8');
  } catch (err) {
    console.error('[STORAGE] Error saving JSON data:', err.message);
  }
}

// Safely gets PIN string regardless of legacy or object format
function getSavedPin(contacts, callerNumber) {
  const entry = contacts[callerNumber];
  if (!entry) return null;
  if (typeof entry === 'string') return entry;
  return entry.pin || null;
}

// -------------------------------------------------------------
// 1. Health Check & Config Endpoints
// -------------------------------------------------------------
app.get('/', (req, res) => {
  res.send('Mobile Call Shield Backend (Telnyx) Active');
});

app.get('/api/shield-number', (req, res) => {
  res.json({
    shieldNumber: SHIELD_PHONE_NUMBER
  });
});

app.get('/api/debug-passphrases', (req, res) => {
  try {
    const data = loadData();
    res.json({
      status: 'success',
      storageFileExists: fs.existsSync(PASSPHRASE_FILE),
      totalContacts: Object.keys(data.contacts).length,
      data: data
    });
  } catch (err) {
    console.error('[DEBUG ERROR]', err);
    res.status(500).json({ status: 'error', error: err.message });
  }
});

// =============================================================
// TELNYX INBOUND VOICE ROUTES & PASSPHRASE MANAGEMENT
// =============================================================

// -------------------------------------------------------------
// Voice Step 1: Initial Call Entry Point
// -------------------------------------------------------------
app.post('/voice', (req, res) => {
  const callerNumber = req.body?.From || req.body?.from || 'Unknown';
  console.log('[VOICE] Incoming call from:', callerNumber);

  const db = loadData();
  const existingPin = getSavedPin(db.contacts, callerNumber);

  res.type('text/xml');

  // FIRST-TIME CALLER: Route to /voice/setup to create and save a PIN
  if (!existingPin) {
    console.log(`[VOICE] New caller ${callerNumber} -> Routing to /voice/setup`);
    const xmlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Gather input="dtmf" action="${BASE_URL}/voice/setup" method="POST" timeout="5" numDigits="4" finishOnKey="#">
        <Say voice="Polly.Joanna-Neural">
            Welcome to Mobile Call Shield. Please enter a 4-digit code on your keypad, followed by the pound key.
        </Say>
    </Gather>
    <Redirect method="POST">${BASE_URL}/voice/voicemail</Redirect>
</Response>`;
    return res.send(xmlResponse);
  }

  // RETURNING CALLER: Route to /voice/process to verify existing PIN
  console.log(`[VOICE] Returning caller ${callerNumber} -> Routing to /voice/process`);
  const xmlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Gather input="dtmf" action="${BASE_URL}/voice/process" method="POST" timeout="5" numDigits="4" finishOnKey="#">
        <Say voice="Polly.Joanna-Neural">
            Thank you for calling Mobile Call Shield. Please enter your 4-digit code on your keypad now.
        </Say>
    </Gather>
    <Redirect method="POST">${BASE_URL}/voice/voicemail</Redirect>
</Response>`;

  res.send(xmlResponse);
});

// -------------------------------------------------------------
// Voice Step 2: Setup / Change Passphrase (4-Digit PIN)
// -------------------------------------------------------------
app.post('/voice/setup', (req, res) => {
  const callerNumber = req.body?.From || req.body?.from || 'Unknown';
  const digits = req.body?.Digits || req.body?.digits || '';
  const newPin = digits.trim();

  console.log(`[VOICE SETUP] ${callerNumber} set PIN: "${newPin}"`);

  res.type('text/xml');

  if (newPin.length === 4) {
    const db = loadData();
    db.contacts[callerNumber] = {
      pin: newPin,
      allowed: true,
      updatedAt: new Date().toISOString()
    };
    saveData(db);

    const xmlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="Polly.Joanna-Neural">Your code has been saved. Connecting your call now.</Say>
    <Dial timeout="20" callerId="${callerNumber}">${OWNER_PHONE_NUMBER}</Dial>
</Response>`;
    return res.send(xmlResponse);
  }

  // Failed setup -> Send to Voicemail
  const xmlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Redirect method="POST">${BASE_URL}/voice/voicemail</Redirect>
</Response>`;
  res.send(xmlResponse);
});

// -------------------------------------------------------------
// Voice Step 3: Process & Verify PIN
// -------------------------------------------------------------
app.post('/voice/process', (req, res) => {
  const callerNumber = req.body?.From || req.body?.from || 'Unknown';
  const digits = req.body?.Digits || req.body?.digits || '';
  const userPin = digits.trim();

  const db = loadData();
  const savedPin = getSavedPin(db.contacts, callerNumber);

  console.log(`[VOICE VERIFY] ${callerNumber} entered PIN: "${userPin}" (Saved: "${savedPin}")`);

  res.type('text/xml');

  // Verify 4-Digit PIN
  if (userPin && userPin === savedPin) {
    const xmlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="Polly.Joanna-Neural">Code verified. Connecting your call now.</Say>
    <Dial timeout="20" callerId="${callerNumber}">${OWNER_PHONE_NUMBER}</Dial>
</Response>`;
    return res.send(xmlResponse);
  }

  // Verification FAILURE -> Redirect to Voicemail
  const xmlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="Polly.Joanna-Neural">Invalid code.</Say>
    <Redirect method="POST">${BASE_URL}/voice/voicemail</Redirect>
</Response>`;

  res.send(xmlResponse);
});

// -------------------------------------------------------------
// Voice Step 4: Voicemail Recording Route
// -------------------------------------------------------------
app.post('/voice/voicemail', (req, res) => {
  res.type('text/xml');

  const xmlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="Polly.Joanna-Neural">
        Please leave a message after the tone. Press pound when finished.
    </Say>
    <Record
        action="${BASE_URL}/voice/voicemail-complete"
        method="POST"
        maxLength="60"
        finishOnKey="#"
        playBeep="true"
    />
    <Say voice="Polly.Joanna-Neural">Thank you. Your message has been saved. Goodbye.</Say>
    <Hangup/>
</Response>`;

  res.send(xmlResponse);
});

// -------------------------------------------------------------
// Voice Step 5: Voicemail Callback & SMS Notification
// -------------------------------------------------------------
app.post('/voice/voicemail-complete', async (req, res) => {
  const callerNumber = req.body?.From || req.body?.from || 'Unknown Caller';
  const recordingUrl = req.body?.RecordingUrl || req.body?.recording_url || '';

  console.log(`[VOICEMAIL] New message from ${callerNumber}: ${recordingUrl}`);

  if (recordingUrl && process.env.TELNYX_API_KEY) {
    try {
      await telnyx.messages.create({
        from: SHIELD_PHONE_NUMBER,
        to: OWNER_PHONE_NUMBER,
        text: `Mobile Call Shield Alert: New voicemail from ${callerNumber}.\n\nListen here: ${recordingUrl}`
      });
      console.log(`[SMS] Voicemail alert sent to ${OWNER_PHONE_NUMBER}`);
    } catch (err) {
      console.error('[SMS ERROR] Failed to send voicemail alert:', err.message);
    }
  }

  res.type('text/xml');
  const xmlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="Polly.Joanna-Neural">Thank you. Your message has been saved. Goodbye.</Say>
    <Hangup/>
</Response>`;

  res.send(xmlResponse);
});

// -------------------------------------------------------------
// Telnyx Inbound SMS Webhook
// -------------------------------------------------------------
app.post('/sms', async (req, res) => {
  try {
    const data = req.body?.data || req.body;
    const eventType = data.event_type || req.body?.event_type;

    if (eventType && eventType !== 'message.received') {
      console.log(`[SMS] Ignoring non-inbound event: ${eventType}`);
      return res.status(200).send('Event ignored');
    }

    const payload = data.payload || data;
    const fromNumber = payload.from?.phone_number || payload.from || payload.From;
    const toNumber = payload.to?.[0]?.phone_number || payload.to || SHIELD_PHONE_NUMBER;
    const messageText = (payload.text || payload.Body || '').trim();

    console.log(`[SMS] Incoming text from ${fromNumber}: "${messageText}"`);

    if (fromNumber === toNumber) {
      console.log('[SMS] Guard triggered: loop prevented.');
      return res.status(200).send('Loop prevented');
    }

    let replyText = 'Command not recognized. Valid commands: ALERTS ON/OFF, SET PASSPHRASE [word], SET GUARDIAN [number].';
    const textUpper = messageText.toUpperCase();

    if (textUpper === 'ALERTS ON') {
      replyText = 'Shield Alerts enabled. You will receive SMS alerts for unverified calls.';
    } else if (textUpper === 'ALERTS OFF') {
      replyText = 'Shield Alerts disabled.';
    } else if (textUpper.startsWith('SET PASSPHRASE ')) {
      const newPassphrase = messageText.substring(15).trim();
      replyText = `Passphrase updated successfully to: "${newPassphrase}".`;
    } else if (textUpper.startsWith('SET GUARDIAN ')) {
      const guardianNum = messageText.substring(13).trim();
      replyText = `Guardian notification number set to: ${guardianNum}.`;
    }

    await telnyx.messages.create({
      from: toNumber,
      to: fromNumber,
      text: replyText
    });

    console.log(`[SMS] Reply sent to ${fromNumber}`);
    res.status(200).send('OK');
  } catch (err) {
    console.error('[SMS] Error handling webhook:', err.message);
    res.status(200).send('Error processed');
  }
});

// -------------------------------------------------------------
// WebSocket Server for Live Audio Screening
// -------------------------------------------------------------
wss.on('connection', (ws) => {
  console.log('[Media Stream] WebSocket client connected');

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);

      if (data.event === 'start') {
        console.log(`[Media Stream] Started for Call Session: ${data.start.call_session_id || data.start.call_control_id}`);
      } else if (data.event === 'media') {
        // Audio processing logic
      } else if (data.event === 'stop') {
        console.log('[Media Stream] Stopped');
      }
    } catch (e) {
      console.error('[Media Stream] Message parse error:', e.message);
    }
  });

  ws.on('close', () => {
    console.log('[Media Stream] WebSocket client disconnected');
  });
});

// -------------------------------------------------------------
// Start Server
// -------------------------------------------------------------
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
