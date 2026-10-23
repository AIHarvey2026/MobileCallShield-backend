const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const twilio = require('twilio');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
app.use(express.json());

// Configure Nodemailer Transporter (Declared ONLY ONCE)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Trust reverse proxy (Render) for express-rate-limit
app.set('trust proxy', 1);

// ----------------------------------------------------
// 1. Database Connection (PostgreSQL on Render)
// ----------------------------------------------------
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});
// ----------------------------------------------------
// 2. Middleware Configuration
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

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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
// Login tokens (JWT)
// ----------------------------------------------------
function signToken(user) {
    if (!process.env.JWT_SECRET) {
        console.error('[Auth] JWT_SECRET is not set; no login token issued.');
        return null;
    }
    return jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
}

function authRequired(req, res, next) {
    if (process.env.REQUIRE_AUTH === 'false') {
        req.userId = req.query.userId || (req.body && req.body.userId);
        return req.userId ? next() : res.status(400).json({ error: 'User ID is required.' });
    }
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : '';
    try {
        req.userId = jwt.verify(token, process.env.JWT_SECRET).id;
        next();
    } catch (e) {
        res.status(401).json({ error: 'Please sign in again.' });
    }
}

function toE164(raw) {
    const text = String(raw || '').trim();
    const digits = text.replace(/\D/g, '');
    if (digits.length === 10) return '+1' + digits;
    if (digits.length === 11 && digits[0] === '1') return '+' + digits;
    if (text.startsWith('+') && digits.length >= 8 && digits.length <= 15) return '+' + digits;
    return null;
}

// Health Check Endpoint
app.get('/health', (req, res) => {
    res.status(200).send('Mobile Call Shield Backend is active and healthy.');
});

// App Settings Endpoint
app.get('/api/settings', async (req, res) => {
    try {
        res.json({
            success: true,
            settings: {
                app_name: "Mobile Call Shield",
                logo_url: ""
            }
        });
    } catch (err) {
        console.error('Error fetching settings:', err);
        res.status(500).json({ error: 'Server error fetching settings.' });
    }
});

// ==========================================
// 3. SECURITY MANAGEMENT ENDPOINTS
// ==========================================

app.put('/api/user/update-owner-pin', async (req, res) => {
    const { userId, currentPin, newPin } = req.body;
    if (!userId || !currentPin || !newPin) {
        return res.status(400).json({ error: 'User ID, current PIN, and new PIN are required.' });
    }
    try {
        const userResult = await pool.query('SELECT pin FROM users WHERE id = $1', [userId]);
        if (userResult.rows.length === 0) return res.status(404).json({ error: 'User not found.' });

        const dbPin = userResult.rows[0].pin || '1234';
        if (currentPin !== dbPin) {
            return res.status(401).json({ success: false, error: 'Incorrect current Owner PIN.' });
        }

        await pool.query('UPDATE users SET pin = $1 WHERE id = $2', [newPin, userId]);
        res.json({ success: true, message: 'Owner PIN updated successfully!' });
    } catch (err) {
        console.error('Error updating Owner PIN:', err);
        res.status(500).json({ error: 'Server error updating Owner PIN.' });
    }
});

app.post('/api/settings/update-passcode', async (req, res) => {
    const { userId, pin, newPasscode } = req.body;
    if (!userId || !pin || !newPasscode) {
        return res.status(400).json({ error: 'User ID, PIN, and new passcode phrase are required.' });
    }
    try {
        const userCheck = await pool.query('SELECT pin FROM users WHERE id = $1', [userId]);
        if (userCheck.rows.length === 0) return res.status(404).json({ error: 'User not found.' });

        const currentDbPin = userCheck.rows[0].pin || '1234';
        if (currentDbPin !== pin) {
            return res.status(401).json({ error: 'Incorrect Owner PIN.' });
        }

        await pool.query('UPDATE users SET passcode = $1 WHERE id = $2', [newPasscode, userId]);
        res.status(200).json({ success: true, message: 'Screening Passcode Phrase updated successfully!' });
    } catch (err) {
        console.error('Error updating passcode:', err);
        res.status(500).json({ error: 'Server error updating screening passcode.' });
    }
});

app.put('/api/user/update-pin', async (req, res) => {
    const { userId, currentPin, newPin } = req.body;
    if (!userId || !currentPin || !newPin) {
        return res.status(400).json({ error: 'User ID, current PIN, and new PIN are required.' });
    }
    try {
        const userResult = await pool.query('SELECT guardian_code FROM users WHERE id = $1', [userId]);
        if (userResult.rows.length === 0) return res.status(404).json({ error: 'User not found.' });

        const dbPin = userResult.rows[0].guardian_code || '1234';
        if (currentPin !== dbPin) {
            return res.status(401).json({ success: false, error: 'Incorrect current Guardian Code.' });
        }

        await pool.query('UPDATE users SET guardian_code = $1 WHERE id = $2', [newPin, userId]);
        res.json({ success: true, message: 'Guardian Code updated successfully!' });
    } catch (err) {
        console.error('Error updating Guardian Code:', err);
        res.status(500).json({ error: 'Server error updating Guardian Code.' });
    }
});

// ----------------------------------------------------
// 4. Subscription Sync
// ----------------------------------------------------
app.post('/api/subscription/sync', async (req, res) => {
    const { userId, originalTransactionId, isTrial } = req.body;
    if (!userId) return res.status(400).json({ error: 'User ID is required.' });

    try {
        await pool.query(
            `UPDATE users SET subscription_status = $1, original_transaction_id = $2 WHERE id = $3`,
            [isTrial ? 'trialing' : 'active', originalTransactionId, userId]
        );
        res.json({ success: true, message: 'Subscription status synced with Apple StoreKit.' });
    } catch (err) {
        console.error('Error syncing StoreKit transaction:', err);
        res.status(500).json({ error: 'Server error syncing subscription.' });
    }
});

// ----------------------------------------------------
// 5. User Authentication Routes
// ----------------------------------------------------
app.post('/api/auth/register', authLimiter, async (req, res) => {
    const { name, phoneNumber, email, password, pin, passcode } = req.body;
    if (!password || !email || !pin) {
        return res.status(400).json({ error: 'Email, password, and PIN are required.' });
    }

    const realPhone = (phoneNumber && phoneNumber !== '+10000000000') ? phoneNumber : null;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

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

        const newUser = await client.query(
            `INSERT INTO users (user_name, owner_phone, email, password, pin, passcode, subscription_status, trial_ends_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, 'trialing', $7, NOW())
             RETURNING id, user_name, owner_phone, email, passcode, subscription_status`,
            [name || email, realPhone, email, passwordHash, pin, userPasscode, trialEnd]
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

app.post('/api/auth/login', authLimiter, async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
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
                subscriptionStatus: user.subscription_status || 'trialing',
                isAdmin: user.is_admin || false
            }
        });
    } catch (err) {
        console.error('Error during login:', err);
        res.status(500).json({ error: 'Server error logging in.' });
    }
});

app.post('/api/setup', authRequired, async (req, res) => {
    const { owner_phone, phone_number, passphrase, pin } = req.body || {};
    const phone = toE164(owner_phone || phone_number);
    const phrase = String(passphrase || '').trim();

    if (!phone) return res.status(400).json({ error: 'Please enter a full mobile number with area code.' });
    if (phrase.length < 4) return res.status(400).json({ error: 'The passphrase needs at least 4 characters.' });
    if (!/^\d{4,6}$/.test(String(pin || ''))) return res.status(400).json({ error: 'The PIN must be 4 to 6 digits.' });

    try {
        const result = await pool.query(
            `UPDATE public.users SET owner_phone = $1, passcode = $2, pin = $3, setup_complete = true WHERE id = $4 RETURNING id, email, owner_phone`,
            [phone, phrase, String(pin), req.userId]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'User record not found.' });
        res.json({ success: true, message: 'Setup completed successfully!', user: result.rows[0] });
    } catch (err) {
        if (err.code === '23505') return res.status(409).json({ error: 'That phone number is already used by another account.' });
        res.status(500).json({ error: 'Database update failed.' });
    }
});

// ----------------------------------------------------
// 6. Twilio Voice Webhooks
// ----------------------------------------------------
app.post('/voice', async (req, res) => {
    const twilioNumber = req.body.To;
    const twiml = new twilio.twiml.VoiceResponse();
    try {
        const userResult = await pool.query(`
            SELECT u.id, u.owner_phone, u.is_call_shield_enabled
            FROM twilio_numbers pn JOIN users u ON pn.user_id = u.id
            WHERE pn.phone_number = $1 AND pn.is_active = true
        `, [twilioNumber]);

        if (userResult.rows.length > 0) {
            const user = userResult.rows[0];
            if (user.is_call_shield_enabled !== true) {
                twiml.dial(user.owner_phone);
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
            gather.say({ voice: 'Polly.Joanna-Neural' }, 'Hello! Please state your name or passcode after the tone.');
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

app.post('/process-passphrase', async (req, res) => {
    const twiml = new twilio.twiml.VoiceResponse();
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
            twiml.dial(user.owner_phone);
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
    const twiml = new twilio.twiml.VoiceResponse();
    twiml.say({ voice: 'Polly.Joanna-Neural' }, 'Thank you. Goodbye.');
    twiml.hangup();
    res.type('text/xml');
    res.send(twiml.toString());
});

// ----------------------------------------------------
// 7. Trusted Contacts & Guardian Routes
// ----------------------------------------------------
app.get('/api/trusted-contacts/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const result = await pool.query(`
            SELECT c.contact_id AS id,
                   ocr.owner_id AS user_id,
                   c.contact_name AS name,
                   COALESCE(ocr.is_active, true) AS is_active,
                   COALESCE(ocr.is_guardian, false) AS is_guardian,
                   COALESCE(ocr.is_primary, false) AS is_primary,
                   COALESCE(
                       json_agg(cpn.phone_number) FILTER (WHERE cpn.phone_number IS NOT NULL AND cpn.phone_number != ''),
                       '[]'
                   ) AS phone_numbers
            FROM contacts c
            JOIN owner_contact_relationship ocr ON c.contact_id = ocr.contact_id
            LEFT JOIN contact_phone_numbers cpn ON c.contact_id = cpn.contact_id
            WHERE ocr.owner_id = $1 AND COALESCE(ocr.is_active, true) = TRUE
            GROUP BY c.contact_id, ocr.owner_id, c.contact_name, ocr.is_active, ocr.is_guardian, ocr.is_primary
            ORDER BY c.contact_name ASC
        `, [userId]);

        res.json(result.rows);
    } catch (err) {
        console.error('Error fetching trusted contacts:', err);
        res.status(500).json({ error: 'Server error: ' + err.message });
    }
});

// POST /api/trusted-contacts (Single contact add endpoint)
app.post('/api/trusted-contacts', async (req, res) => {
    const { userId, name, phoneNumber } = req.body;
    if (!userId || !name || !phoneNumber) {
        return res.status(400).json({ error: 'User ID, name, and phone number are required.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const contactResult = await client.query(
            'INSERT INTO contacts (contact_name) VALUES ($1) RETURNING contact_id',
            [name]
        );
        const contactId = contactResult.rows[0].contact_id;

        await client.query(`
            INSERT INTO owner_contact_relationship (owner_id, contact_id, is_active, is_guardian)
            VALUES ($1, $2, TRUE, FALSE)
        `, [userId, contactId]);

        await client.query(`
            INSERT INTO contact_phone_numbers (contact_id, phone_number)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING
        `, [contactId, phoneNumber]);

        await client.query('COMMIT');

        res.status(201).json({
            success: true,
            message: 'Trusted contact added successfully.',
            contact: { id: contactId, name, phone: phoneNumber }
        });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error adding trusted contact:', err);
        res.status(500).json({ error: 'Server error adding trusted contact.' });
    } finally {
        client.release();
    }
});

app.delete('/api/trusted-contacts/:id', async (req, res) => {
    const contactId = req.params.id;
    const { userId } = req.query;
    try {
        const result = await pool.query(
            'UPDATE owner_contact_relationship SET is_active = FALSE WHERE contact_id = $1 AND owner_id = $2',
            [contactId, userId]
        );
        if (result.rowCount === 0) return res.status(404).json({ error: 'Contact relationship not found.' });
        res.json({ success: true, message: 'Contact deactivated successfully.' });
    } catch (err) {
        console.error('Error deleting contact:', err);
        res.status(500).json({ error: 'Server error deleting contact.' });
    }
});

app.post('/api/trusted-contacts/bulk', async (req, res) => {
    const { userId, contacts } = req.body;
    if (!userId || !contacts || !Array.isArray(contacts)) {
        return res.status(400).json({ error: "Invalid payload format" });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        for (const contact of contacts) {
            const contactName = contact.name || 'Unknown';
            const phoneNumbers = Array.isArray(contact.phone_numbers)
                ? contact.phone_numbers
                : (contact.phone_number ? [contact.phone_number] : []);

            if (phoneNumbers.length === 0) continue;

            let contactId;
            const existingContactQuery = await client.query(`
                SELECT c.contact_id FROM contacts c
                JOIN owner_contact_relationship ocr ON c.contact_id = ocr.contact_id
                WHERE ocr.owner_id = $1 AND c.contact_name = $2
            `, [userId, contactName]);

            if (existingContactQuery.rows.length > 0) {
                contactId = existingContactQuery.rows[0].contact_id;
                await client.query(`UPDATE owner_contact_relationship SET is_active = TRUE WHERE owner_id = $1 AND contact_id = $2`, [userId, contactId]);
            } else {
                const contactResult = await client.query('INSERT INTO contacts (contact_name) VALUES ($1) RETURNING contact_id', [contactName]);
                contactId = contactResult.rows[0].contact_id;
                await client.query(`INSERT INTO owner_contact_relationship (owner_id, contact_id, is_active) VALUES ($1, $2, TRUE)`, [userId, contactId]);
            }

            for (const number of phoneNumbers) {
                await client.query(`INSERT INTO contact_phone_numbers (contact_id, phone_number) VALUES ($1, $2) ON CONFLICT DO NOTHING`, [contactId, number]);
            }
        }
        await client.query('COMMIT');
        res.status(201).json({ success: true, message: 'Contacts synced successfully.' });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error in bulk contact insert:', err);
        res.status(500).json({ error: 'Server error during contact sync.' });
    } finally {
        client.release();
    }
});

// GET /api/guardians/:userId - Returns array of all guardians & overall protection status
app.get('/api/guardians/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
       
        // Fetch guardian contacts
        const guardiansResult = await pool.query(`
            SELECT c.contact_id AS id,
                   c.contact_name AS name,
                   cpn.phone_number AS phone,
                   ocr.is_primary,
                   ocr.is_guardian
            FROM contacts c
            JOIN owner_contact_relationship ocr ON c.contact_id = ocr.contact_id
            LEFT JOIN contact_phone_numbers cpn ON c.contact_id = cpn.contact_id
            WHERE ocr.owner_id = $1 AND ocr.is_guardian = TRUE AND ocr.is_active = TRUE
            ORDER BY ocr.is_primary DESC, c.contact_name ASC
        `, [userId]);

        // Fetch shield active status from users table
        const userResult = await pool.query(`
            SELECT COALESCE(is_shield_active, true) AS is_shield_active FROM users WHERE id = $1
        `, [userId]);

        const isShieldActive = userResult.rows.length > 0 ? userResult.rows[0].is_shield_active : true;

        res.json({
            success: true,
            isShieldActive: isShieldActive,
            guardians: guardiansResult.rows
        });
    } catch (err) {
        console.error('Error fetching guardians:', err);
        res.status(500).json({ error: 'Server error fetching guardian details.' });
    }
});

// POST /api/guardians/toggle-shield - Requires Guardian PIN to switch ON/OFF
app.post('/api/guardians/toggle-shield', async (req, res) => {
    const { userId, guardianPin, isShieldActive } = req.body;

    try {
        const userResult = await pool.query('SELECT guardian_code FROM users WHERE id = $1', [userId]);
        if (userResult.rows.length === 0) return res.status(404).json({ error: 'User not found.' });

        const dbGuardianCode = userResult.rows[0].guardian_code || '1234';
        if (guardianPin !== dbGuardianCode) {
            return res.status(401).json({ success: false, error: 'Incorrect Guardian PIN.' });
        }

        await pool.query('UPDATE users SET is_shield_active = $1 WHERE id = $2', [isShieldActive, userId]);
        res.json({ success: true, isShieldActive });
    } catch (err) {
        console.error('Error toggling shield:', err);
        res.status(500).json({ error: 'Server error updating shield status.' });
    }
});

// POST /api/guardians/send-report
app.post('/api/guardians/send-report', async (req, res) => {
    const { userId, guardianPin, reportType } = req.body;

    if (!userId || !guardianPin) {
        return res.status(400).json({ error: 'User ID and Guardian PIN are required.' });
    }

    try {
        const userResult = await pool.query('SELECT guardian_code, user_name, email FROM users WHERE id = $1', [userId]);
        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }

        const dbGuardianCode = userResult.rows[0].guardian_code || '1234';
        if (guardianPin !== dbGuardianCode) {
            return res.status(401).json({ success: false, error: 'Incorrect Guardian PIN.' });
        }

        const userName = userResult.rows[0].user_name || 'Senior User';
        const targetEmail = userResult.rows[0].email;

        let timeInterval = "INTERVAL '7 days'";
        if (reportType === 'daily') timeInterval = "INTERVAL '1 day'";
        if (reportType === 'monthly') timeInterval = "INTERVAL '30 days'";

        const logsResult = await pool.query(`
            SELECT caller_phone, called_phone, status, voicemail_url, created_at
            FROM call_logs
            WHERE user_id = $1 AND created_at >= NOW() - ${timeInterval}
            ORDER BY created_at DESC
        `, [userId]);

        const logs = logsResult.rows;

        let logsHtml = logs.length === 0 ? '<p>No call logs found for this period.</p>' : `
            <table style="width:100%; border-collapse: collapse; font-size: 14px;">
                <tr style="background-color: #f1f5f9; text-align: left;">
                    <th style="padding: 8px; border: 1px solid #cbd5e1;">Time</th>
                    <th style="padding: 8px; border: 1px solid #cbd5e1;">Caller</th>
                    <th style="padding: 8px; border: 1px solid #cbd5e1;">Status</th>
                    <th style="padding: 8px; border: 1px solid #cbd5e1;">Voicemail</th>
                </tr>
                ${logs.map(log => `
                    <tr>
                        <td style="padding: 8px; border: 1px solid #cbd5e1;">${new Date(log.created_at).toLocaleString()}</td>
                        <td style="padding: 8px; border: 1px solid #cbd5e1;">${log.caller_phone}</td>
                        <td style="padding: 8px; border: 1px solid #cbd5e1;">${log.status}</td>
                        <td style="padding: 8px; border: 1px solid #cbd5e1;">${log.voicemail_url ? `<a href="${log.voicemail_url}">Play Audio</a>` : 'None'}</td>
                    </tr>
                `).join('')}
            </table>
        `;

        // Dispatch email via Nodemailer
        await transporter.sendMail({
            from: '"Senior Scam Shield Guardian" <support@mobilecallshield.com>',
            to: targetEmail,
            subject: `Call Activity Report for ${userName}`,
            html: `
                <div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 8px;">
                    <h2 style="color: #2563eb; margin-top: 0;">Call Log Summary Report</h2>
                    <p>Here is the call activity report for <strong>${userName}</strong>:</p>
                    ${logsHtml}
                    <p style="margin-top: 30px; font-size: 12px; color: #64748b;">Generated securely via Guardian PIN verification.</p>
                </div>
            `
        });

        res.json({ success: true, message: 'Report emailed successfully.' });
    } catch (err) {
        console.error('Error sending guardian report:', err);
        res.status(500).json({ error: 'Server error sending report: ' + err.message });
    }
});
        await transporter.sendMail({
            from: '"Mobile Call Shield - Guardian" <support@mobilecallshield.com>',
            to: targetEmail,
            subject: `Call Activity Report for ${userName}`,
            html: `
                <div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 8px;">
                    <h2 style="color: #2563eb; margin-top: 0;">Call Log Report (${reportType || '7 days'})</h2>
                    <p>Here is the call activity summary for <strong>${userName}</strong>:</p>
                    ${logsHtml}
                    <p style="margin-top: 30px; font-size: 12px; color: #64748b;">Verified via Guardian PIN.</p>
                </div>
            `
        });

        res.json({ success: true, message: 'Report emailed successfully.' });
    } catch (err) {
        console.error('Error sending guardian report:', err);
        res.status(500).json({ error: 'Server error sending report.' });
    }
});


// ----------------------------------------------------
// Call Logs
// ----------------------------------------------------
// GET /api/call-logs/:userId?startDate=YYYY-MM-DD&endDate=YYYY-MM-DD
app.get('/api/call-logs/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const { startDate, endDate } = req.query;

        let query = `
            SELECT id, user_id, caller_phone, called_phone, status, voicemail_url, created_at
            FROM call_logs
            WHERE user_id = $1
        `;
        const queryParams = [userId];

        if (startDate && endDate) {
            queryParams.push(startDate, `${endDate} 23:59:59`);
            query += ` AND created_at BETWEEN $2 AND $3`;
        }

        query += ` ORDER BY id DESC LIMIT 100`;

        const result = await pool.query(query, queryParams);
        res.json({ success: true, logs: result.rows });
    } catch (err) {
        console.error('Error fetching call logs:', err);
        res.status(500).json({ error: 'Server error fetching call logs: ' + err.message });
    }
});


// ----------------------------------------------------
// Server Listen
// ----------------------------------------------------
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});