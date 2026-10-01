const express = require('express');
const twilio = require('twilio');

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Health check route for UptimeRobot
app.get('/health', (req, res) => {
    res.status(200).send('OK');
});

// Primary voice webhook called by Twilio
app.post('/voice', (req, res) => {
    console.log('[CALL] Incoming call received from:', req.body.From);

    const twiml = new twilio.twiml.VoiceResponse();

    const gather = twiml.gather({
        input: 'speech',
        action: '/verify-passphrase',
        timeout: 5,
        speechTimeout: 'auto'
    });
    gather.say('Hello. Please state your passphrase to proceed.');

    // Fallback if no speech is detected
    twiml.say('We did not receive any input. Goodbye.');

    res.type('text/xml');
    res.send(twiml.toString());
});

// Passphrase verification route
app.post('/verify-passphrase', (req, res) => {
    const speechResult = (req.body.SpeechResult || '').toLowerCase();
    console.log('[PASSPHRASE] Speech detected:', speechResult);

    const twiml = new twilio.twiml.VoiceResponse();

    if (speechResult.includes('blue monkey')) {
        twiml.say('Passphrase accepted. Connecting your call.');
        // Replace +1XXXXXXXXXX with your real cell number to test direct forwarding
        const dial = twiml.dial();
        dial.number('+18324254469');
    } else {
        twiml.say('Passphrase incorrect. Please leave a message after the tone.');
        twiml.record({
            maxLength: 30,
            action: '/voicemail-complete'
        });
    }

    res.type('text/xml');
    res.send(twiml.toString());
});

app.post('/voicemail-complete', (req, res) => {
    const twiml = new twilio.twiml.VoiceResponse();
    twiml.say('Thank you. Your message has been recorded. Goodbye.');
    res.type('text/xml');
    res.send(twiml.toString());
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`MobileCallShield server running on port ${PORT}`);
});

