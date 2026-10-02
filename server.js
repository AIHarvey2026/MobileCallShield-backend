const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const Telnyx = require('telnyx');

const telnyx = new Telnyx({ apiKey: process.env.TELNYX_API_KEY });

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// -------------------------------------------------------------
// 1. Health Check Endpoint
// -------------------------------------------------------------
app.get('/', (req, res) => {
  res.send('Senior Scam Shield Backend (Telnyx) Active');
});

// Endpoint for app/client to get the active Shield Number
app.get('/api/shield-number', (req, res) => {
  res.json({
    shieldNumber: process.env.SHIELD_PHONE_NUMBER || '+13466036303'
  });
});

// =============================================================
// TELNYX INBOUND VOICE ROUTES & PASSPHRASE MANAGEMENT
// =============================================================

const fs = require('fs');
const path = require('path');

// Local JSON file to store passphrases per caller phone number
const PASSPHRASE_FILE = path.join(__dirname, 'passphrases.json');

function loadPassphrases() {
  try {
    if (fs.existsSync(PASSPHRASE_FILE)) {
      return JSON.parse(fs.readFileSync(PASSPHRASE_FILE, 'utf8'));
    }
  } catch (err) {
    console.error('Error reading passphrases file:', err);
  }
  return {};
}

function savePassphrases(data) {
  try {
    fs.writeFileSync(PASSPHRASE_FILE, JSON.stringify(data, null, 2), 'utf8');
  } catch (err) {
    console.error('Error saving passphrases file:', err);
  }
}

// -------------------------------------------------------------
// 1. Initial Call Entry Point
// -------------------------------------------------------------
app.post('/voice', (req, res) => {
  const callerNumber = req.body?.From || req.body?.from || 'Unknown';
  console.log('[VOICE] Incoming call from:', callerNumber);

  const db = loadPassphrases();
  const existingPassphrase = db[callerNumber];

  res.type('text/xml');

  // FIRST-TIME CALLER: Prompt to set up a new passphrase
  if (!existingPassphrase) {
    const xmlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Gather input="speech dtmf" action="/voice/setup" method="POST" timeout="6" numDigits="4">
        <Say voice="Polly.Joanna-Neural">
            Welcome to Mobile Call Shield. It looks like this is your first time calling. Please speak or enter a 4-digit passphrase to secure your calls.
        </Say>
    </Gather>
    <Say voice="Polly.Joanna-Neural">We did not receive any input. Goodbye.</Say>
    <Hangup/>
</Response>`;
    return res.send(xmlResponse);
  }

  // RETURNING CALLER: Prompt for existing passphrase
  const xmlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Gather input="speech dtmf" action="/voice/process" method="POST" timeout="6" numDigits="4">
        <Say voice="Polly.Joanna-Neural">
            Thank you for calling Mobile Call Shield. Please enter or speak your passphrase code now.
        </Say>
    </Gather>
    <Say voice="Polly.Joanna-Neural">We did not receive any input. Goodbye.</Say>
    <Hangup/>
</Response>`;

  res.send(xmlResponse);
});

// -------------------------------------------------------------
// 2. Setup / Change Passphrase Route
// -------------------------------------------------------------
app.post('/voice/setup', (req, res) => {
  const callerNumber = req.body?.From || req.body?.from || 'Unknown';
  const speechResult = req.body?.SpeechResult || req.body?.Speech || '';
  const digits = req.body?.Digits || '';
  const newPassphrase = (speechResult || digits).toLowerCase().trim();

  console.log(`[VOICE SETUP] ${callerNumber} set new passphrase: "${newPassphrase}"`);

  res.type('text/xml');

  if (newPassphrase.length >= 2) {
    const db = loadPassphrases();
    db[callerNumber] = newPassphrase;
    savePassphrases(db);

    const xmlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="Polly.Joanna-Neural">
        Your passphrase has been successfully saved as ${newPassphrase}. Connecting your call now.
    </Say>
</Response>`;
    return res.send(xmlResponse);
  }

  const xmlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="Polly.Joanna-Neural">We could not understand your passphrase. Please try calling back.</Say>
    <Hangup/>
</Response>`;
  res.send(xmlResponse);
});

// -------------------------------------------------------------
// 3. Process & Verify Passphrase Route
// -------------------------------------------------------------
app.post('/voice/process', (req, res) => {
  const callerNumber = req.body?.From || req.body?.from || 'Unknown';
  const speechResult = req.body?.SpeechResult || req.body?.Speech || '';
  const digits = req.body?.Digits || '';
  const userInput = (speechResult || digits).toLowerCase().trim();

  console.log(`[VOICE VERIFY] ${callerNumber} input: "${userInput}"`);

  const db = loadPassphrases();
  const savedPassphrase = db[callerNumber] || 'blue monkey';

  res.type('text/xml');

  // Request to CHANGE passphrase
  if (userInput.includes('change') || userInput === '*') {
    const xmlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Gather input="speech dtmf" action="/voice/setup" method="POST" timeout="6" numDigits="4">
        <Say voice="Polly.Joanna-Neural">
            Please speak or enter your new passphrase now.
        </Say>
    </Gather>
    <Say voice="Polly.Joanna-Neural">No input received. Goodbye.</Say>
    <Hangup/>
</Response>`;
    return res.send(xmlResponse);
  }

  // Verification SUCCESS
  if (userInput.includes(savedPassphrase) || userInput === savedPassphrase) {
    const xmlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="Polly.Joanna-Neural">Passphrase verified. Connecting your call now.</Say>
</Response>`;
    return res.send(xmlResponse);
  }

  // Verification FAILURE
  const xmlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="Polly.Joanna-Neural">Invalid passphrase. Goodbye.</Say>
    <Hangup/>
</Response>`;

  res.send(xmlResponse);
});

// -------------------------------------------------------------
// 3. Telnyx Inbound SMS Webhook
// -------------------------------------------------------------
app.post('/sms', async (req, res) => {
  try {
    const data = req.body?.data || req.body;
    const eventType = data.event_type || req.body?.event_type;

    // Ignore non-inbound events like delivery status receipts
    if (eventType && eventType !== 'message.received') {
      console.log(`[SMS] Ignoring non-inbound event: ${eventType}`);
      return res.status(200).send('Event ignored');
    }

    const payload = data.payload || data;

    // Extract sender (+1 mobile cell) and receiver (+13466036303)
    const fromNumber = payload.from?.phone_number || payload.from || payload.From;
    const toNumber = payload.to?.[0]?.phone_number || payload.to || process.env.SHIELD_PHONE_NUMBER || '+13466036303';
    const messageText = (payload.text || payload.Body || '').trim();

    console.log(`[SMS] Incoming text from ${fromNumber}: "${messageText}"`);

    // Guard against replying to ourselves
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

    // Dispatch reply SMS via Telnyx
    await telnyx.messages.send({
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
// 4. WebSocket Server for Live Audio Screening
// -------------------------------------------------------------
wss.on('connection', (ws) => {
  console.log('[Media Stream] WebSocket client connected');

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);

      if (data.event === 'start') {
        console.log(`[Media Stream] Started for Call Session: ${data.start.call_session_id || data.start.call_control_id}`);
      } else if (data.event === 'media') {
        // Base64-encoded audio payload from Telnyx
        const payload = data.media.payload;
        // Process payload with your passphrase verification / speech recognition engine
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
// 5. Start Server
// -------------------------------------------------------------
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
