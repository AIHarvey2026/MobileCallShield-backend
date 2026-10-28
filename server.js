require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const twilio = require('twilio');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const path = require('path');
const bodyParser = require('body-parser');

// 1. Initialize Express FIRST
const app = express();
const PORT = process.env.PORT || 3000;

// 2. Middleware & Static Files
app.use(express.static('public'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.json());

// Add the profanity filter package import here:
const { profanity } = require('@2toad/profanity');


// Trust reverse proxy (Render) for express-rate-limit
app.set('trust proxy', 1);

// Configuration
const TWILIO_NUMBER = process.env.TWILIO_PHONE_NUMBER || '+18005550199';
const { VoiceResponse } = twilio.twiml;

// ----------------------------------------------------
// Database Connection (PostgreSQL on Render)
// ----------------------------------------------------
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// ----------------------------------------------------
// CORS Configuration
// ----------------------------------------------------
const allowedOrigins = [
    'https://mobilecallshield.com',
    'https://www.mobilecallshield.com',
    'http://localhost:3000'
];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(null, true);
        }
    },
    credentials: true
}));

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        error: "Too many authentication attempts from this device. Please try again after 15 minutes."
    }
});

// ----------------------------------------------------
// JWT Helpers
// ----------------------------------------------------
function signToken(user) {
    if (!process.env.JWT_SECRET) {
        console.error('[Auth] JWT_SECRET is not set; no login token issued.');
        return null;
    }
    return jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
}

function toE164(raw) {
    const text = String(raw || '').trim();
    const digits = text.replace(/\D/g, '');
    if (digits.length === 10) return '+1' + digits;
    if (digits.length === 11 && digits[0] === '1') return '+' + digits;
    if (text.startsWith('+') && digits.length >= 8 && digits.length <= 15) return '+' + digits;
    return null;
}

// ... existing phone helpers ...

function normalizeIncomingPhone(rawFrom) {
    if (!rawFrom) return null;
    const digitsOnly = rawFrom.replace(/\D/g, '');
    const tenDigits = digitsOnly.slice(-10);
    if (tenDigits.length !== 10) return rawFrom;
    return `(${tenDigits.slice(0, 3)}) ${tenDigits.slice(3, 6)}-${tenDigits.slice(6)}`;
}

// ----------------------------------------------------
// Message Name Validation & Profanity Sanitizer
// ----------------------------------------------------
function sanitizeAndValidateMessageName(nameInput) {
    // 1. Convert blank or whitespace-only inputs to null
    if (!nameInput || nameInput.trim() === '') {
        return null;
    }
    
    const cleanName = nameInput.trim();
    
    // 2. Reject names containing bad words
    if (profanity.exists(cleanName)) {
        throw new Error('Message name contains inappropriate language. Please choose a different name.');
    }
    
    return cleanName;
}

// ----------------------------------------------------
// Update Message Name Endpoint (For User Settings / Profile)
// ----------------------------------------------------
app.post('/api/user/update-message-name', async (req, res) => {
    const { userId, rawMessageName } = req.body;

    if (!userId) {
        return res.status(400).json({ success: false, error: 'User ID is required.' });
    }

    try {
        // Run validation check (converts empty to null, throws error if profane)
        const sanitizedName = sanitizeAndValidateMessageName(rawMessageName);

        // Save sanitized name (or null) to database
        const result = await pool.query(
            'UPDATE users SET message_name = $1 WHERE id = $2 RETURNING id, message_name',
            [sanitizedName, userId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, error: 'User not found.' });
        }

        res.json({
            success: true,
            message: sanitizedName 
                ? `Greeting name updated to "${sanitizedName}".` 
                : 'Greeting name cleared. Calls will use the default privacy message.',
            messageName: sanitizedName
        });
    } catch (err) {
        // Return 400 if profanity error was caught
        console.error('Error updating message name:', err);
        res.status(400).json({ success: false, error: err.message || 'Failed to update message name.' });
    }
});


// Nodemailer Transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// ----------------------------------------------------
// Core Routes
// ----------------------------------------------------
app.get('/health', (req, res) => {
    res.status(200).send('Mobile Call Shield Backend is active and healthy.');
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ----------------------------------------------------
// Authentication & Setup Routes
// ----------------------------------------------------

app.post('/api/auth/register', authLimiter, async (req, res) => {
    const { name, phoneNumber, email, password, pin, passcode, messageName } = req.body;
    if (!password || !email || !pin) {
        return res.status(400).json({ error: 'Email, password, and PIN are required.' });
    }

    const realPhone = (phoneNumber && phoneNumber !== '+10000000000') ? phoneNumber : null;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Sanitize and validate message_name (throws error if profane, returns null if blank)
        let sanitizedMessageName = null;
        try {
            sanitizedMessageName = sanitizeAndValidateMessageName(messageName);
        } catch (validationErr) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: validationErr.message });
        }

        const existingUser = await client.query(
            'SELECT id FROM users WHERE ($1::text IS NOT NULL AND owner_phone = $1) OR email = $2',
            [realPhone, email]
        );

        if (existingUser.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(409).json({ error: 'An account with this phone number or email already exists.' });
        }

        const userPasscode = passcode || '1234';
        const passwordHash = await bcrypt.hash(String(password), 10);
        const trialEnd = new Date();
        trialEnd.setDate(trialEnd.getDate() + 14);

        // Insert including message_name
        const newUser = await client.query(
            `INSERT INTO users (user_name, owner_phone, email, password, pin, passcode, message_name, subscription_status, trial_ends_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, 'trialing', $8, NOW())
             RETURNING id, user_name, owner_phone, email, passcode, message_name, subscription_status`,
            [name || email, realPhone, email, passwordHash, pin, userPasscode, sanitizedMessageName, trialEnd]
        );

        const newUserId = newUser.rows[0].id;

        const availablePhoneQuery = await client.query(
            `SELECT id, phone_number FROM twilio_numbers
             WHERE is_active = false OR user_id IS NULL
             ORDER BY id ASC LIMIT 1 FOR UPDATE`
        );

        let assignedPhoneNumber = null;
        if (availablePhoneQuery.rows.length > 0) {
            const phoneRow = availablePhoneQuery.rows[0];
            assignedPhoneNumber = phoneRow.phone_number;
            await client.query(
                `UPDATE twilio_numbers SET user_id = $1, is_active = true WHERE id = $2`,
                [newUserId, phoneRow.id]
            );
        }

        await client.query('COMMIT');

        res.status(201).json({
            success: true,
            message: 'User registered successfully!',
            token: signToken({ id: newUserId }),
            user: {
                id: newUserId,
                name: newUser.rows[0].user_name,
                phoneNumber: newUser.rows[0].owner_phone,
                assignedTwilioNumber: assignedPhoneNumber,
                email: newUser.rows[0].email,
                passcode: newUser.rows[0].passcode,
                messageName: newUser.rows[0].message_name,
                subscriptionStatus: newUser.rows[0].subscription_status
            }
        });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error during registration:', err);
        res.status(500).json({ error: 'Server error creating user account.' });
    } finally {
        client.release();
    }
});

// Login Code
app.post('/api/auth/login', authLimiter, async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query(`
            SELECT u.*, tn.phone_number as twilio_screening_number
            FROM users u
            LEFT JOIN twilio_numbers tn ON u.id = tn.user_id AND tn.is_active = true
            WHERE u.email = $1
        `, [email]);

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials: User not found.' });
        }

        const user = result.rows[0];
        const isPlain = password === user.password;
        const match = isPlain || await bcrypt.compare(String(password || ''), String(user.password || '')).catch(() => false);

        if (!match) {
            return res.status(401).json({ error: 'Invalid credentials: Password incorrect.' });
        }

        res.status(200).json({
            success: true,
            message: 'Login successful!',
            token: signToken(user),
            user: {
                id: user.id,
                name: user.user_name,
                phoneNumber: user.owner_phone,
                email: user.email,
                carrierName: user.carrier_name,
                twilioNumber: user.twilio_screening_number,
                subscriptionStatus: user.subscription_status || 'trialing',
                isAdmin: user.is_admin || false
            }
        });
    } catch (err) {
        console.error('Error during login:', err);
        res.status(500).json({ error: 'Server error logging in.' });
    }
});


// ----------------------------------------------------
// Guardian Management Endpoints
// ----------------------------------------------------

// 1. Get guardians for a user (dependent)
app.get('/api/guardians/:userId', async (req, res) => {
    const { userId } = req.params;
    try {
        const result = await pool.query(
            `SELECT ag.id, ag.guardian_user_id as guardianUserId, ag.permission_level as relationship, ag.created_at as createdAt
             FROM account_guardians ag
             WHERE ag.dependent_user_id = $1`,
            [userId]
        );
        res.status(200).json(result.rows);
    } catch (err) {
        console.error('Error fetching guardians:', err);
        res.status(500).json({ error: 'Server error fetching guardians.' });
    }
});

// 2. Add a guardian relationship
app.post('/api/guardians', async (req, res) => {
    const { dependentUserId, guardianUserId, permissionLevel } = req.body;
    if (!dependentUserId || !guardianUserId) {
        return res.status(400).json({ error: 'Dependent User ID and Guardian User ID are required.' });
    }

    try {
        const result = await pool.query(
            `INSERT INTO account_guardians (dependent_user_id, guardian_user_id, permission_level)
             VALUES ($1, $2, $3)
             RETURNING id, dependent_user_id as dependentUserId, guardian_user_id as guardianUserId, permission_level as relationship`,
            [dependentUserId, guardianUserId, permissionLevel || 'full']
        );
        res.status(201).json({ success: true, guardian: result.rows[0] });
    } catch (err) {
        console.error('Error creating guardian:', err);
        res.status(500).json({ error: 'Server error creating guardian.' });
    }
});

// 3. Delete a guardian relationship
app.delete('/api/guardians/:guardianId', async (req, res) => {
    const { guardianId } = req.params;
    try {
        await pool.query('DELETE FROM account_guardians WHERE id = $1', [guardianId]);
        res.status(200).json({ success: true, message: 'Guardian deleted successfully.' });
    } catch (err) {
        console.error('Error deleting guardian:', err);
        res.status(500).json({ error: 'Server error deleting guardian.' });
    }
});

// ----------------------------------------------------
// Account Deactivation Endpoint
// ----------------------------------------------------
app.post('/api/user/deactivate', async (req, res) => {
  const { userId, guardianPin } = req.body;

  if (!userId) {
    return res.status(400).json({ error: 'Missing userId' });
  }

  try {
    const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userResult.rows[0];

    if (user.primary_guardian_id) {
      if (!guardianPin) {
        return res.status(401).json({ error: 'Primary Guardian PIN required' });
      }
      const guardianResult = await pool.query('SELECT * FROM guardians WHERE id = $1 AND pin = $2', [user.primary_guardian_id, guardianPin]);
      if (guardianResult.rows.length === 0) {
        return res.status(401).json({ error: 'Incorrect Guardian PIN' });
      }
    }

    await pool.query('UPDATE users SET is_active = false WHERE id = $1', [userId]);

    res.json({
      success: true,
      message: 'Account successfully deactivated and subscription stopped.'
    });

  } catch (error) {
    console.error('Deactivation error:', error);
    res.status(500).json({ error: 'Internal server error during deactivation' });
  }
});

// ----------------------------------------------------
// Toggle Shield Status (Added for iOS & Android Parity)
// ----------------------------------------------------
app.put('/api/user/toggle-shield', async (req, res) => {
    const { userId, isEnabled, pin } = req.body;
    if (!userId) {
        return res.status(400).json({ error: 'User ID is required.' });
    }

    try {
        const userResult = await pool.query('SELECT pin, guardian_code FROM users WHERE id = $1', [userId]);
        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }

        const dbPin = userResult.rows[0].guardian_code || userResult.rows[0].pin || '1234';

        if (!isEnabled && pin && pin !== dbPin) {
            return res.status(401).json({ success: false, error: 'Incorrect Guardian/Owner PIN.' });
        }

        await pool.query('UPDATE users SET is_call_shield_enabled = $1 WHERE id = $2', [isEnabled, userId]);
        res.json({ success: true, message: `Shield status updated to ${isEnabled}` });
    } catch (err) {
        console.error('Error toggling shield:', err);
        res.status(500).json({ error: 'Server error updating shield status.' });
    }
});

app.post('/api/guardians/send-alert', async (req, res) => {
    const { userId, guardianPhone, alertMessage } = req.body;
    
    if (!guardianPhone || !alertMessage) {
        return res.status(400).json({ error: 'Guardian phone number and alert message are required.' });
    }

    try {
        const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
        await client.messages.create({
            body: `[MobileCallShield Alert] ${alertMessage}`,
            from: process.env.TWILIO_PHONE_NUMBER,
            to: guardianPhone
        });

        res.json({ success: true, message: 'SMS alert successfully dispatched to guardian.' });
    } catch (err) {
        console.error('Error dispatching SMS alert via Twilio:', err);
        res.status(500).json({ error: 'Failed to send SMS alert.' });
    }
})

// ----------------------------------------------------
// Adminstration Section
// ----------------------------------------------------


// Get all users for Admin Dashboard
app.get('/api/admin/users', authenticateToken, async (req, res) => {
    try {
        // Ensure only admins can access this
        if (!req.user.is_admin && req.user.role !== 'admin') {
            return res.status(403).json({ success: false, error: 'Access denied. Admins only.' });
        }

        const result = await pool.query('SELECT id, user_name AS name, owner_phone AS phone_number, email, role, is_admin FROM users ORDER BY id ASC');
        res.json(result.rows);
    } catch (err) {
        console.error('Error fetching admin users:', err);
        res.status(500).json({ success: false, error: 'Server error' });
    }
});



// ----------------------------------------------------
// Twilio Call Screening Webhooks
// ----------------------------------------------------
app.post('/whisper', (req, res) => {
    const twiml = new VoiceResponse();
    const gather = twiml.gather({
        numDigits: 1,
        action: '/process-whisper',
        method: 'POST',
        timeout: 5
    });
    gather.say({ voice: 'Polly.Joanna-Neural' }, 'Incoming Call Shield connection. Press 1 to accept.');
    twiml.hangup();
    res.type('text/xml');
    res.send(twiml.toString());
});

// ====================================================
// 1. UPDATED VOICE WEBHOOK (WITH message_name SUPPORT)
// ====================================================
app.post('/voice', async (req, res) => {
    const twilioNumber = req.body.To;
    const rawCallerId = req.body.From;
    const normalizedCallerId = normalizeIncomingPhone(rawCallerId);
    
    const twiml = new VoiceResponse();
    try {
        // Query message_name instead of user_name
        const userResult = await pool.query(`
            SELECT u.id, u.message_name, u.owner_phone, u.is_call_shield_enabled
            FROM twilio_numbers pn JOIN users u ON pn.user_id = u.id
            WHERE pn.phone_number = $1 AND pn.is_active = true
        `, [twilioNumber]);

        if (userResult.rows.length > 0) {
            const user = userResult.rows[0];
            const announcedName = user.message_name || null;

            // Build dynamic prompt based on whether message_name is set or NULL
            let greetingPrompt = '';
            if (announcedName) {
                greetingPrompt = `Hello! This call is protected by Mobile Call Shield for ${announcedName}. Please enter your guardian PIN or passcode to continue.`;
            } else {
                greetingPrompt = `Hello! This call is protected by Mobile Call Shield. Please enter your guardian PIN or passcode to continue.`;
            }

            const dialUser = (twimlResponse) => {
                const protocol = req.headers['x-forwarded-proto'] || 'https';
                const whisperUrl = `${protocol}://${req.headers.host}/whisper`;
                const voicemailUrl = `${protocol}://${req.headers.host}/handle-voicemail`;

                const dial = twimlResponse.dial({
                    callerId: twilioNumber,
                    answerOnBridge: true,
                    timeout: 20,
                    timeLimit: 900,
                    action: voicemailUrl
                });
                dial.number({ url: whisperUrl }, user.owner_phone);
            };

            if (user.is_call_shield_enabled !== true) {
                dialUser(twiml);
                res.type('text/xml');
                return res.send(twiml.toString());
            }

            const contactQuery = `
                SELECT c.contact_id, c.contact_name 
                FROM contacts c
                JOIN contact_phone_numbers cpn ON c.contact_id = cpn.contact_id
                JOIN owner_contact_relationship ocr ON c.contact_id = ocr.contact_id
                WHERE ocr.owner_id = $1 
                  AND ocr.is_active = TRUE 
                  AND cpn.phone_number = $2
                LIMIT 1;
            `;
            const contactResult = await pool.query(contactQuery, [user.id, normalizedCallerId]);

            if (contactResult.rows.length > 0) {
                dialUser(twiml);
                res.type('text/xml');
                return res.send(twiml.toString());
            }

            const gather = twiml.gather({
                input: 'speech dtmf',
                numDigits: 4,
                action: '/process-passphrase',
                method: 'POST',
                timeout: 5,
                speechTimeout: 'auto'
            });
            gather.say({ voice: 'Polly.Joanna-Neural' }, greetingPrompt);
            
            twiml.say({ voice: 'Polly.Joanna-Neural' }, 'We did not receive any input. Goodbye.');
            twiml.hangup();

            res.type('text/xml');
            return res.send(twiml.toString());
        }
    } catch (err) {
        console.error('Error in voice webhook:', err);
    }
    twiml.say({ voice: 'Polly.Joanna-Neural' }, 'No active account found. Goodbye.');
    twiml.hangup();
    res.type('text/xml');
    res.send(twiml.toString());
});


// ====================================================
// 2. UPDATED VOICEMAIL GREETING HANDLER
// ====================================================
app.post('/handle-voicemail', async (req, res) => {
    const dialStatus = req.body.DialCallStatus;
    const twilioNumber = req.body.To;
    const twiml = new VoiceResponse();

    try {
        const userResult = await pool.query(`
            SELECT u.message_name 
            FROM twilio_numbers pn JOIN users u ON pn.user_id = u.id
            WHERE pn.phone_number = $1 AND pn.is_active = true
        `, [twilioNumber]);

        const messageName = userResult.rows.length > 0 ? userResult.rows[0].message_name : null;
        
        // Use message_name if available, else use privacy fallback
        const unavailabilityPrompt = messageName 
            ? `${messageName} is currently unavailable. Please leave a message after the tone.` 
            : `The user is currently unavailable. Please leave a message after the tone.`;

        if (dialStatus !== 'completed') {
            twiml.say({ voice: 'Polly.Joanna-Neural' }, unavailabilityPrompt);
            twiml.record({
                action: '/save-recording',
                method: 'POST',
                maxLength: 120,
                playBeep: true,
                finishOnKey: '#'
            });
            twiml.say({ voice: 'Polly.Joanna-Neural' }, 'We did not receive a recording. Goodbye.');
        } else {
            twiml.hangup();
        }
    } catch (err) {
        console.error('Error handling voicemail greeting:', err);
        twiml.say({ voice: 'Polly.Joanna-Neural' }, 'The user is currently unavailable. Please leave a message after the tone.');
        twiml.record({
            action: '/save-recording',
            method: 'POST',
            maxLength: 120,
            playBeep: true,
            finishOnKey: '#'
        });
    }

    res.type('text/xml');
    res.send(twiml.toString());
});


// ====================================================
// 3. SAVE RECORDING & SEND NOTIFICATION
// ====================================================
app.post('/save-recording', async (req, res) => {
    const recordingUrl = req.body.RecordingUrl;
    const callerNumber = req.body.From;
    const calledNumber = req.body.To;

    console.log(`New voicemail received from ${callerNumber} on ${calledNumber}: ${recordingUrl}`);

    try {
        const userResult = await pool.query(`
            SELECT u.owner_phone, u.message_name, u.sms_notifications_enabled 
            FROM twilio_numbers pn JOIN users u ON pn.user_id = u.id
            WHERE pn.phone_number = $1 AND pn.is_active = true
        `, [calledNumber]);

        if (userResult.rows.length > 0) {
            const { owner_phone, message_name, sms_notifications_enabled } = userResult.rows[0];
            const recipientName = message_name || 'you';

            const sendSms = sms_notifications_enabled === true || sms_notifications_enabled === null;

            if (owner_phone && sendSms && typeof client !== 'undefined') {
                await client.messages.create({
                    body: `Mobile Call Shield: New voicemail from ${callerNumber} for ${recipientName}. Listen here: ${recordingUrl}`,
                    to: owner_phone,
                    from: calledNumber
                });
                console.log(`Voicemail SMS notification successfully sent to ${owner_phone}`);
            } else {
                console.log(`Voicemail received, but SMS notifications are disabled for this user.`);
            }
        }
    } catch (err) {
        console.error('Error handling voicemail notification:', err);
    }

    const twiml = new VoiceResponse();
    twiml.say({ voice: 'Polly.Joanna-Neural' }, 'Thank you. Your message has been saved. Goodbye.');
    twiml.hangup();

    res.type('text/xml');
    res.send(twiml.toString());
});

app.post('/process-passphrase', async (req, res) => {
    const twiml = new VoiceResponse();
    const spokenPassphrase = (req.body.SpeechResult || '').toLowerCase().trim();
    const twilioNumber = req.body.To;
    const callerPhone = req.body.From;

    try {
        const userResult = await pool.query(`
            SELECT u.passcode, u.owner_phone, u.id
            FROM twilio_numbers pn JOIN users u ON pn.user_id = u.id
            WHERE pn.phone_number = $1 AND pn.is_active = true
        `, [twilioNumber]);

        if (userResult.rows.length === 0) {
            twiml.hangup();
            res.type('text/xml');
            return res.send(twiml.toString());
        }

        const user = userResult.rows[0];
        const userPasscode = (user.passcode || '1234').toLowerCase().trim();

        const trustedCheck = await pool.query(`
            SELECT 1 FROM contact_phone_numbers cpn
            JOIN owner_contact_relationship ocr ON cpn.contact_id = ocr.contact_id
            WHERE ocr.owner_id = $1 AND cpn.phone_number = $2 AND ocr.is_active = TRUE
        `, [user.id, callerPhone]);

        if (trustedCheck.rows.length > 0 || (spokenPassphrase.length > 0 && spokenPassphrase.includes(userPasscode))) {
            twiml.say({ voice: 'Polly.Joanna-Neural' }, 'Connecting your call now.');
            twiml.dial({ 
                callerId: twilioNumber,
                answerOnBridge: true,
                timeout: 20,
                action: '/api/twilio/handle-missed-call',
                method: 'POST'
            }, user.owner_phone);
        } else {
            twiml.say({ voice: 'Polly.Joanna-Neural' }, 'Passcode not recognized. Please leave a message after the tone.');
            twiml.record({ action: '/save-voicemail', method: 'POST', maxLength: 60, finishOnKey: '#' });
        }
    } catch (err) {
        console.error('Error processing passphrase:', err);
        twiml.hangup();
    }
    res.type('text/xml');
    res.send(twiml.toString());
});

// Loop prevention handler if owner misses the 2nd ring
app.post('/api/twilio/handle-missed-call', (req, res) => {
    const twiml = new VoiceResponse();
    const dialStatus = req.body.DialCallStatus;

    if (dialStatus === 'completed') {
        twiml.hangup();
    } else {
        twiml.say({ voice: 'Polly.Joanna-Neural' }, 'The person you are trying to reach is unavailable. Please leave a message after the tone.');
        twiml.record({
            action: '/save-voicemail',
            method: 'POST',
            maxLength: 60,
            transcribe: true
        });
    }
    res.type('text/xml');
    res.send(twiml.toString());
});

app.post('/save-voicemail', async (req, res) => {
    const recordingUrl = req.body.RecordingUrl;
    const callerNumber = req.body.From;
    const calledNumber = req.body.To;
    try {
        const userResult = await pool.query(`
            SELECT u.id FROM twilio_numbers pn JOIN users u ON pn.user_id = u.id
            WHERE pn.phone_number = $1 AND pn.is_active = true
        `, [calledNumber]);

        if (userResult.rows.length > 0) {
            const userId = userResult.rows[0].id;
            await pool.query(`
                UPDATE call_logs SET voicemail_url = $1
                WHERE user_id = $2 AND caller_phone = $3 AND voicemail_url IS NULL
                AND created_at >= NOW() - INTERVAL '10 minutes'
            `, [`${recordingUrl}.mp3`, userId, callerNumber]);
        }
    } catch (err) {
        console.error('Error saving voicemail:', err);
    }
    const twiml = new VoiceResponse();
    twiml.say({ voice: 'Polly.Joanna-Neural' }, 'Thank you. Goodbye.');
    twiml.hangup();
    res.type('text/xml');
    res.send(twiml.toString());
});

// ----------------------------------------------------
// Server Listen
// ----------------------------------------------------
app.listen(PORT, () => {
    console.log(`Mobile Call Shield server running on port ${PORT}`);
});