require('dotenv').config();
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const twilio = require('twilio');
const bodyParser = require('body-parser');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

const userDatabase = new Map();

// 1. Settings sync endpoint for iOS app
app.post('/api/user/settings', (req, res) => {
    const { deviceId, seniorPhone, secretWord, guardianName, guardianPhone, isAudioMonitoringEnabled, isPassphraseRequired, spamRouteAction } = req.body;
    console.log(`[SYNC] Settings received for Device ID: ${deviceId}`);

    let user = userDatabase.get(deviceId) || {};
    user = {
        ...user,
        deviceId,
        seniorPhone,
        secretWord: secretWord || "blue monkey",
        guardianName,
        guardianPhone,
        isAudioMonitoringEnabled: isAudioMonitoringEnabled ?? true,
        isPassphraseRequired: isPassphraseRequired ?? true,
        spamRouteAction: spamRouteAction ?? 0,
        lastUpdated: new Date()
    };

    userDatabase.set(deviceId, user);
    res.status(200).json({ status: "success", message: "User settings saved." });
});

// 2. VoIP Token registration endpoint
app.post('/api/user/register-voip', (req, res) => {
    const { deviceId, voipToken, platform } = req.body;
    console.log(`[SYNC] Registered ${platform} VoIP Push Token for Device ID: ${deviceId}`);

    let user = userDatabase.get(deviceId) || { deviceId };
    user.voipToken = voipToken;
    user.platform = platform;
    userDatabase.set(deviceId, user);

    res.status(200).json({ status: "success", message: "VoIP token registered." });
});

// 3. Twilio Voice Webhook
app.post('/voice', (req, res) => {
    const twiml = new twilio.twiml.VoiceResponse();
    const callerNumber = req.body.From;
    const calledNumber = req.body.To;

    console.log(`[CALL] Incoming call from ${callerNumber} to ${calledNumber}`);

    const user = Array.from(userDatabase.values()).find(u => u.seniorPhone === calledNumber) || {
        isAudioMonitoringEnabled: true,
        isPassphraseRequired: true,
        secretWord: "blue monkey"
    };

    if (user.isPassphraseRequired) {
        const gather = twiml.gather({
            input: 'speech',
            action: '/verify-passphrase',
            timeout: 5,
            speechTimeout: 'auto'
        });
        gather.say('Hello. This line is protected by Senior Scam Shield. Please state the passphrase to connect.');
        twiml.say('No passphrase received. Goodbye.');
        twiml.hangup();

        res.type('text/xml');
        return res.send(twiml.toString());
    }

    if (user.isAudioMonitoringEnabled) {
        const connect = twiml.connect();
        const stream = connect.stream({
            url: `wss://${process.env.SERVER_DOMAIN}/stream`
        });
        stream.parameter({ name: 'caller', value: callerNumber });
    }

    const dial = twiml.dial();
    dial.client('senior_user_client');

    res.type('text/xml');
    res.send(twiml.toString());
});

// 4. Passphrase Verification
app.post('/verify-passphrase', (req, res) => {
    const twiml = new twilio.twiml.VoiceResponse();
    const speechResult = req.body.SpeechResult ? req.body.SpeechResult.toLowerCase() : '';

    console.log(`[PASSPHRASE] Speech detected: "${speechResult}"`);

    if (speechResult.includes('blue monkey') || speechResult.includes('passphrase')) {
        twiml.say('Passphrase verified. Connecting your call.');
        const dial = twiml.dial();
        dial.client('senior_user_client');
    } else {
        twiml.say('Invalid passphrase. Call terminated.');
        twiml.hangup();
    }

    res.type('text/xml');
    res.send(twiml.toString());
});

// 5. WebSocket Audio Stream
wss.on('connection', (ws) => {
    console.log('[WEBSOCKET] Twilio media stream connected.');

    ws.on('message', (message) => {
        const msg = JSON.parse(message);
        if (msg.event === 'start') {
            console.log(`[STREAM] Audio stream started - SID: ${msg.streamSid}`);
        }
    });

    ws.on('close', () => {
        console.log('[WEBSOCKET] Audio stream ended.');
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`SeniorScamShield server running on port ${PORT}`);
});
