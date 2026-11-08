require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const twilio = require('twilio');
const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const path = require('path');
const bodyParser = require('body-parser');
const { profanity } = require('@2toad/profanity');
const cron = require('node-cron'); // <--- ADD THIS LINE

// 1. Initialize Express FIRST
const app = express();
const PORT = process.env.PORT || 3000;

// Trust reverse proxy (Render) for express-rate-limit
app.set('trust proxy', 1);
app.use(bodyParser.urlencoded({ extended: true }));

// 2. Database Connection (PostgreSQL on Render)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// 3. Global Middleware & Static Files
app.use(express.static('public'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.json());

// Configuration & Constants
const TWILIO_NUMBER = process.env.TWILIO_PHONE_NUMBER || '+18005550199';
const { VoiceResponse } = twilio.twiml;

// CORS Configuration
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

// --- Twilio SMS Helper Function ---
async function sendGuardianSMS(toPhoneNumber, messageBody) {
    if (!toPhoneNumber) return;
    try {
        await twilioClient.messages.create({
            body: messageBody,
            from: process.env.TWILIO_PHONE_NUMBER || TWILIO_NUMBER,
            to: toPhoneNumber
        });
        console.log(`[SMS Alert Sent] To: ${toPhoneNumber}`);
    } catch (err) {
        console.error('[SMS Alert Error] Failed to send guardian SMS:', err);
    }
}

// --- Nodemailer Transporter for Custom Domain (support@mobilecallshield.com) ---
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '465', 10),
    secure: parseInt(process.env.SMTP_PORT || '465', 10) === 465, // true for 465, false for 587
    auth: {
        user: process.env.ADMIN_EMAIL || process.env.EMAIL_USER,
        pass: process.env.ADMIN_EMAIL_PASS || process.env.EMAIL_PASS
    }
});

async function sendLowInventoryAlert(count) {
    const mailOptions = {
        from: process.env.ADMIN_EMAIL || process.env.EMAIL_USER,
        to: process.env.ADMIN_EMAIL || process.env.EMAIL_USER,
        subject: '⚠️ URGENT: Mobile Call Shield Number Inventory Low',
        text: `Warning! Your available carrier phone number pool is running low.\n\nRemaining unassigned numbers: ${count}\n\nPlease log into your Telnyx or carrier dashboard immediately to purchase more numbers to prevent onboarding failures for new users.`
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log('Low inventory alert email sent successfully.');
    } catch (error) {
        console.error('Failed to send inventory alert email:', error);
    }
}

// ----------------------------------------------------
// JWT & Helper Functions
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

function normalizeIncomingPhone(rawFrom) {
    if (!rawFrom) return null;
    const digitsOnly = rawFrom.replace(/\D/g, '');
    const tenDigits = digitsOnly.slice(-10);
    if (tenDigits.length !== 10) return rawFrom;
    return `(${tenDigits.slice(0, 3)}) ${tenDigits.slice(3, 6)}-${tenDigits.slice(6)}`;
}

function sanitizeAndValidateMessageName(nameInput) {
    if (!nameInput || nameInput.trim() === '') {
        return null;
    }
    const cleanName = nameInput.trim();
    if (profanity.exists(cleanName)) {
        throw new Error('Message name contains inappropriate language. Please choose a different name.');
    }
    return cleanName;
}

// -----------------------------------------------------------------------------------------
// 4. JWT Authentication Middleware
// -----------------------------------------------------------------------------------------
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Expects "Bearer <token>"
   
    if (!token) {
        return res.status(401).json({ success: false, error: 'Access token required.' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_key', (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, error: 'Invalid or expired token.' });
        }
        req.user = user;
        next();
    });
};

// ----------------------------------------------------
// 5. Core Routes
// ----------------------------------------------------
app.get('/health', (req, res) => {
    res.status(200).send('Mobile Call Shield Backend is active and healthy.');
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ----------------------------------------------------
// Administration Section (Protected)
// ----------------------------------------------------
app.get('/api/admin/users', authenticateToken, async (req, res) => {
    try {
        const userCheck = await pool.query('SELECT is_admin FROM users WHERE id = $1', [req.user.id]);
        if (userCheck.rows.length === 0 || !userCheck.rows[0].is_admin) {
            return res.status(403).json({ success: false, error: 'Access denied. Admins only.' });
        }

        const result = await pool.query('SELECT id, user_name AS name, owner_phone AS phone_number, email, role, is_admin FROM users ORDER BY id ASC');
        res.json(result.rows);
    } catch (err) {
        console.error('Error fetching admin users:', err);
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

// Inventory Check Endpoint
app.get('/api/admin/check-number-inventory', async (req, res) => {
    try {
	const query = 'SELECT COUNT(*) FROM twilio_numbers WHERE user_id IS NULL OR is_active = false';
        const result = await pool.query(query);
        const availableCount = parseInt(result.rows[0].count, 10);
        
        const threshold = 5; // Alert threshold
        
        if (availableCount <= threshold) {
            await sendLowInventoryAlert(availableCount);
        }

        res.json({
            success: true,
            availableNumbers: availableCount,
            isLowInventory: availableCount <= threshold
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ----------------------------------------------------
// Authentication & Setup Routes
// ----------------------------------------------------

app.post('/api/auth/register', authLimiter, async (req, res) => {
    const { name, phoneNumber, email, password, pin, passcode, messageName, securityQuestion, securityAnswer } = req.body;
    if (!password || !email || !pin) {
        return res.status(400).json({ error: 'Email, password, and PIN are required.' });
    }

    const realPhone = (phoneNumber && phoneNumber !== '+10000000000') ? phoneNumber : null;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

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
        
        const finalQuestion = securityQuestion && securityQuestion.trim() !== '' 
            ? securityQuestion.trim() 
            : "What was the name of your first pet?";
            
        const finalAnswer = securityAnswer && securityAnswer.trim() !== '' 
            ? securityAnswer.trim().toLowerCase() 
            : "fluffy";

        const trialEnd = new Date();
        trialEnd.setDate(trialEnd.getDate() + 14);

        const newUser = await client.query(
            `INSERT INTO users (user_name, owner_phone, email, password, pin, passcode, message_name, security_question, security_answer, subscription_status, trial_ends_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'trialing', $10, NOW())
             RETURNING id, user_name, owner_phone, email, passcode, message_name, security_question, subscription_status`,
            [name || email, realPhone, email, passwordHash, pin, userPasscode, sanitizedMessageName, finalQuestion, finalAnswer, trialEnd]
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

            await client.query(
                `UPDATE users SET twilio_screening_number = $1 WHERE id = $2`,
                [assignedPhoneNumber, newUserId]
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
                twilio_screening_number: assignedPhoneNumber,
                email: newUser.rows[0].email,
                passcode: newUser.rows[0].passcode,
                messageName: newUser.rows[0].message_name,
                securityQuestion: newUser.rows[0].security_question,
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

app.get('/api/settings', (req, res) => {
    res.json({
        success: true,
        settings: {
            app_name: "Mobile Call Shield",
            logo_url: ""
        }
    });
});

// ----------------------------------------------------
// User Settings & Profile
// ----------------------------------------------------
app.post('/api/user/update-message-name', async (req, res) => {
    const { userId, rawMessageName } = req.body;

    if (!userId) {
        return res.status(400).json({ success: false, error: 'User ID is required.' });
    }

    try {
        const sanitizedName = sanitizeAndValidateMessageName(rawMessageName);

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
        console.error('Error updating message name:', err);
        res.status(400).json({ success: false, error: err.message || 'Failed to update message name.' });
    }
});

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

app.get('/api/user/profile', async (req, res) => {
    try {
        const userId = req.query.userId;
        console.log(`[Backend Profile] Incoming request for userId: ${userId}`);

        const result = await pool.query(
            'SELECT id, email, carrier_name, twilio_screening_number, subscription_status FROM users WHERE id = $1',
            [userId]
        );

        if (result.rows.length === 0) {
            console.log(`[Backend Profile] User not found for id: ${userId}`);
            return res.status(404).json({ error: 'User not found' });
        }

        const user = result.rows[0];
        console.log(`[Backend Profile] Found user record:`, user);
        
        res.json({
            user: {
                id: user.id,
                email: user.email,
                carrier_name: user.carrier_name,
                assignedTwilioNumber: user.twilio_screening_number, 
                subscriptionStatus: user.subscription_status
            }
        });

    } catch (err) {
        console.error('[Backend Profile] Error fetching user profile:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ----------------------------------------------------
// Guardian & Trusted Contacts Management
// ----------------------------------------------------
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

app.get('/api/trusted-contacts/:userId', async (req, res) => {
    const { userId } = req.params;
    try {
        const query = `
            SELECT id, name, phone_number, is_guardian, is_primary 
            FROM trusted_contacts 
            WHERE user_id = $1
            ORDER BY name ASC
        `;
        const result = await pool.query(query, [userId]);
        
        const formattedRows = result.rows.map(row => ({
            id: row.id,
            name: row.name,
            phone_numbers: row.phone_number ? [row.phone_number] : [],
            is_guardian: row.is_guardian,
            is_primary: row.is_primary
        }));
        
        res.json(formattedRows);
    } catch (err) {
        console.error("❌ Error fetching trusted contacts:", err);
        res.status(500).json({ error: "Failed to fetch trusted contacts." });
    }
});

app.post('/api/trusted-contacts/bulk', async (req, res) => {
    const { userId, contacts } = req.body;
    
    if (!userId || !contacts || !Array.isArray(contacts)) {
        return res.status(400).json({ error: "userId and contacts array are required." });
    }

    try {
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            for (const contact of contacts) {
                let phone = "";
                if (Array.isArray(contact.phone_numbers) && contact.phone_numbers.length > 0) {
                    phone = contact.phone_numbers[0];
                } else if (contact.phone_number) {
                    phone = contact.phone_number;
                }

                const query = `
                    INSERT INTO trusted_contacts (user_id, name, phone_number, is_guardian, is_primary)
                    VALUES ($1, $2, $3, $4, $5)
                    ON CONFLICT DO NOTHING
                `;
                await client.query(query, [
                    userId,
                    contact.name,
                    phone,
                    contact.is_guardian || false,
                    contact.is_primary || false
                ]);
            }
            await client.query('COMMIT');
            res.status(201).json({ message: "Contacts synced successfully." });
        } catch (dbErr) {
            await client.query('ROLLBACK');
            throw dbErr;
        } finally {
            client.release();
        }
    } catch (err) {
        console.error("❌ Error bulk uploading contacts:", err);
        res.status(500).json({ error: "Server error syncing contacts." });
    }
});

app.patch('/api/trusted-contacts/:contactId/guardian', async (req, res) => {
    const { contactId } = req.params;
    const { is_guardian } = req.body;

    try {
        const query = `
            UPDATE trusted_contacts 
            SET is_guardian = $1 
            WHERE id = $2 
            RETURNING id, name, phone_number, is_guardian, is_primary
        `;
        const result = await pool.query(query, [is_guardian, contactId]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Contact not found." });
        }
        
        const row = result.rows[0];
        res.json({
            id: row.id,
            name: row.name,
            phone_numbers: row.phone_number ? [row.phone_number] : [],
            is_guardian: row.is_guardian,
            is_primary: row.is_primary
        });
    } catch (err) {
        console.error("❌ Error updating guardian status:", err);
        res.status(500).json({ error: "Server error updating guardian status." });
    }
});

app.put('/api/user/update-pin', async (req, res) => {
    const { userId, newPin, pin } = req.body;
    const targetUserId = userId || req.user.id;
    const pinToSave = newPin || pin;

    if (!targetUserId || !pinToSave) {
        return res.status(400).json({ success: false, error: 'User ID and new PIN are required.' });
    }

    try {
        const result = await pool.query(
            'UPDATE users SET pin = $1 WHERE id = $2 RETURNING id, pin',
            [pinToSave.trim(), targetUserId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, error: 'User not found.' });
        }

        res.json({
            success: true,
            message: 'PIN updated successfully!',
            pin: result.rows[0].pin
        });
    } catch (err) {
        console.error('Error updating PIN:', err);
        res.status(500).json({ success: false, error: 'Server error updating PIN.' });
    }
});

app.post('/api/settings/update-passcode', async (req, res) => {
    const { userId, pin, currentPasscode, newPasscode } = req.body;

    if (!userId || !pin || !currentPasscode || !newPasscode) {
        return res.status(400).json({ success: false, error: 'User ID, PIN, current passcode, and new passcode are required.' });
    }

    try {
        const userResult = await pool.query('SELECT id, pin, passcode FROM users WHERE id = $1', [userId]);

        if (userResult.rows.length === 0) {
            return res.status(404).json({ success: false, error: 'User not found.' });
        }

        const user = userResult.rows[0];

        if (String(user.pin).trim() !== String(pin).trim()) {
            return res.status(401).json({ success: false, error: 'Incorrect Owner PIN.' });
        }

        if (String(user.passcode).trim().toLowerCase() !== String(currentPasscode).trim().toLowerCase()) {
            return res.status(401).json({ success: false, error: 'Current passcode phrase does not match.' });
        }

        const result = await pool.query(
            'UPDATE users SET passcode = $1 WHERE id = $2 RETURNING id, passcode',
            [newPasscode.trim(), userId]
        );

        return res.json({
            success: true,
            message: 'Passcode phrase updated successfully!',
            passcode: result.rows[0].passcode
        });

    } catch (err) {
        console.error('Error updating passcode:', err);
        return res.status(500).json({ success: false, error: 'Server error updating passcode.' });
    }
});

// ----------------------------------------------------
// Asynchronous Caller Line-Type & Risk Evaluation
// ----------------------------------------------------
async function evaluateAndLogCallerAsync(CallSid, phoneNumber, userId) {
    try {
        const lookupResult = await twilioClient.lookups.v2.phoneNumbers(phoneNumber)
            .fetch({ fields: ['line_type_intelligence'] });

        const lineTypeData = lookupResult.lineTypeIntelligence;
        const lineType = (lineTypeData?.type || 'UNKNOWN').toUpperCase();
        const carrierName = lineTypeData?.carrierName || 'Unknown Carrier';

        const frequencyQuery = `
            SELECT COUNT(*) AS call_count 
            FROM call_logs 
            WHERE from_number = $1 
              AND created_at >= NOW() - INTERVAL '24 hours';
        `;
        const freqResult = await pool.query(frequencyQuery, [phoneNumber]);
        const callCount = parseInt(freqResult.rows[0].call_count, 10) || 0;

        let label = 'Standard Mobile Line';
        let isHighRisk = false;

        if (lineType === 'VOIP') {
            label = '⚠️ VoIP Burner (High Scam Risk)';
            isHighRisk = true;
        } else if (callCount >= 3) {
            label = '⚠️ Suspicious Mobile (Frequent Caller)';
            isHighRisk = true;
        } else if (lineType === 'LANDLINE') {
            label = 'Landline / Business Line';
        }

        await pool.query(
            `UPDATE call_logs 
             SET line_type = $1, carrier = $2, risk_label = $3 
             WHERE call_sid = $4`,
            [lineType, carrierName, label, CallSid]
        );
        console.log(`[Lookup Complete] Call SID ${CallSid}: Line=${lineType}, Carrier=${carrierName}`);

        // Automatically send SMS alert if flagged as high risk
        if (isHighRisk) {
            const userQuery = await pool.query('SELECT owner_phone FROM users WHERE id = $1', [userId]);
            if (userQuery.rows.length > 0 && userQuery.rows[0].owner_phone) {
                const ownerPhone = userQuery.rows[0].owner_phone;
                const alertMessage = `🛡️ Senior Scam Shield Alert:\nHigh-risk call detected from ${phoneNumber} (${label}). Intercepted by screening system.`;
                await sendGuardianSMS(ownerPhone, alertMessage);
            }
        }

    } catch (err) {
        console.error('[EVALUATE BACKGROUND] Error fetching Twilio lookup:', err);
    }
}

// ----------------------------------------------------
// Twilio Voice Webhook Handler & Passcode Verification
// ----------------------------------------------------
app.post('/api/twilio/voice', async (req, res) => {
    const { CallSid, From, To, CallStatus, Direction } = req.body;
    
    console.log(`[Twilio Webhook] Incoming call: SID=${CallSid}, From=${From}, To=${To}, Status=${CallStatus}`);

    const dbClient = await pool.connect();
    try {
        const userQuery = await dbClient.query(
            `SELECT u.id AS user_id, u.owner_phone, u.is_call_shield_enabled, u.message_name FROM users u 
             JOIN twilio_numbers tn ON u.id = tn.user_id 
             WHERE tn.phone_number = $1 LIMIT 1`,
            [To]
        );

        if (userQuery.rows.length === 0) {
            res.type('text/xml');
            return res.send(new VoiceResponse().say('This number is not active.').toString());
        }

        const user = userQuery.rows[0];
        const userId = user.user_id;

        await dbClient.query(
            `INSERT INTO call_logs (call_sid, user_id, from_number, to_number, call_status, direction, line_type, carrier, risk_label, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, 'PENDING', 'Pending Lookup', 'Evaluating...', NOW())
             ON CONFLICT (call_sid) DO UPDATE 
             SET call_status = EXCLUDED.call_status`,
            [CallSid, userId, From, To, CallStatus || 'ringing', Direction || 'inbound']
        );

        // Run Twilio Lookup asynchronously in the background so call never times out
        evaluateAndLogCallerAsync(CallSid, From, userId);

        const twiml = new VoiceResponse();

        if (user.is_call_shield_enabled === false) {
            if (user.owner_phone) {
                twiml.say('Connecting your call.');
                twiml.dial(user.owner_phone);
            } else {
                twiml.say('Call screening is currently paused, but no owner phone is configured.');
            }
            res.type('text/xml');
            return res.send(twiml.toString());
        }

        const contactCheck = await dbClient.query(
            `SELECT id FROM trusted_contacts WHERE user_id = $1 AND phone_number = $2`,
            [userId, From]
        );
        const isTrusted = contactCheck.rows.length > 0;

        if (isTrusted) {
            twiml.say('Connecting your trusted contact.');
            if (user.owner_phone) {
                twiml.dial(user.owner_phone);
            }
       } else {
            const gather = twiml.gather({
                input: 'speech dtmf',
                action: '/api/twilio/verify-passcode',
                method: 'POST',
                timeout: 5,
                speechTimeout: 'auto'
            });
        
            const greetingName = user.message_name || 'the owner';
            gather.say(`This is Mobile Call Shield protecting ${greetingName}. Please state the passcode or enter it on your keypad. If you are a doctor or medical provider, please press 9 or say doctor.`);

            twiml.say('No passcode received. Please leave a message after the tone.');
            twiml.record({
                action: '/api/twilio/handle-voicemail',
                method: 'POST',
                maxLength: 60,
                transcribe: true,
                transcribeCallback: '/api/twilio/voicemail-transcription'
            });
        }

        res.type('text/xml');
        res.send(twiml.toString());
    } catch (err) {
        console.error('[Twilio Webhook Error] Failed to log or process call:', err);
        const twiml = new VoiceResponse();
        twiml.say('An application error has occurred.');
        res.type('text/xml');
        res.send(twiml.toString());
    } finally {
        dbClient.release();
    }
});

app.post('/api/twilio/verify-passcode', async (req, res) => {
    const { CallSid, Digits, SpeechResult, To } = req.body;
    const isTimeoutFallback = req.query.fallback === 'voicemail';
    const twiml = new VoiceResponse();

    let digitsInput = (Digits || '').trim();
    let speechInput = (SpeechResult || '').toLowerCase().trim();

    if (isTimeoutFallback || (digitsInput === '' && speechInput === '')) {
        digitsInput = '0000';
    }

    let ownerPhone = null;
    let passcode = '1234';
    let dbClient = null;

    try {
        dbClient = await pool.connect();
        const callQuery = await dbClient.query(
            `SELECT c.user_id, u.owner_phone, u.passcode 
             FROM call_logs c 
             JOIN users u ON c.user_id = u.id 
             WHERE c.call_sid = $1 LIMIT 1`,
            [CallSid]
        );

        if (callQuery.rows.length > 0) {
            ownerPhone = callQuery.rows[0].owner_phone;
            passcode = callQuery.rows[0].passcode || '1234';
        } else if (To) {
            const userFallback = await dbClient.query(
                `SELECT u.id, u.owner_phone, u.passcode 
                 FROM users u 
                 JOIN twilio_numbers tn ON u.id = tn.user_id 
                 WHERE tn.phone_number = $1 LIMIT 1`,
                [To]
            );
            if (userFallback.rows.length > 0) {
                ownerPhone = userFallback.rows[0].owner_phone;
                passcode = userFallback.rows[0].passcode || '1234';
            }
        }
    } catch (err) {
        console.error('[Verify Passcode DB Error]:', err);
    } finally {
        if (dbClient) {
            dbClient.release();
        }
    }

    if (digitsInput === '9' || speechInput.includes('doctor') || speechInput.includes('medical')) {
        twiml.say('Connecting your urgent medical call.');
        if (ownerPhone) {
            twiml.dial(ownerPhone);
        } else {
            twiml.say('Owner phone not configured.');
        }
        res.type('text/xml');
        return res.send(twiml.toString());
    }

    const isMatch = (passcode && digitsInput === passcode) || (passcode && speechInput.includes(passcode));

    if (isMatch) {
        twiml.say('Passcode accepted. Connecting your call.');
        if (ownerPhone) {
            twiml.dial(ownerPhone);
        } else {
            twiml.say('Owner phone not configured.');
        }
    } else {
        twiml.say('Passcode not recognized. Please leave a message after the tone.');
        twiml.record({
            action: '/api/twilio/handle-voicemail',
            method: 'POST',
            maxLength: 60,
            transcribe: true,
            transcribeCallback: '/api/twilio/voicemail-transcription'
        });
    }

    res.type('text/xml');
    res.send(twiml.toString());
});

// ----------------------------------------------------
// Voicemail & Transcription Handlers
// ----------------------------------------------------
app.post('/api/twilio/handle-voicemail', async (req, res) => {
    const { CallSid, RecordingUrl } = req.body;
    console.log(`[Voicemail] Recording received for Call SID: ${CallSid}. URL: ${RecordingUrl}`);

    const dbClient = await pool.connect();
    try {
        const updateResult = await dbClient.query(
            `UPDATE call_logs 
             SET voicemail_url = $1, call_status = 'voicemail' 
             WHERE call_sid = $2 
             RETURNING user_id, from_number`,
            [RecordingUrl, CallSid]
        );

        if (updateResult.rows.length > 0) {
            const { user_id, from_number } = updateResult.rows[0];

            const userQuery = await dbClient.query(
                'SELECT owner_phone FROM users WHERE id = $1',
                [user_id]
            );

            if (userQuery.rows.length > 0 && userQuery.rows[0].owner_phone) {
                const guardianPhone = userQuery.rows[0].owner_phone;
                const alertMessage = `🛡️ Senior Scam Shield Alert:\nNew voicemail recorded from unknown caller ${from_number}. Check your app to listen.`;
                
                await sendGuardianSMS(guardianPhone, alertMessage);
            }
        }
    } catch (err) {
        console.error('[Voicemail Error] Failed to update call log or send SMS:', err);
    } finally {
        dbClient.release();
    }

    const twiml = new VoiceResponse();
    twiml.say('Thank you. Your message has been saved. Goodbye.');
    twiml.hangup();

    res.type('text/xml');
    res.send(twiml.toString());
});

app.post('/api/twilio/voicemail-transcription', async (req, res) => {
    const { CallSid, TranscriptionText, TranscriptionStatus } = req.body;

    if (TranscriptionStatus === 'completed' && TranscriptionText) {
        console.log(`[Transcription Success] Call SID ${CallSid}: "${TranscriptionText}"`);

        const dbClient = await pool.connect();
        try {
            await dbClient.query(
                `UPDATE call_logs 
                 SET voicemail_text = $1 
                 WHERE call_sid = $2`,
                [TranscriptionText, CallSid]
            );
        } catch (err) {
            console.error('[Transcription Error] Failed to save transcript to database:', err);
        } finally {
            dbClient.release();
        }
    } else {
        console.log(`[Transcription Status] Call SID ${CallSid} status: ${TranscriptionStatus}`);
    }

    res.status(200).send('OK');
});

// ----------------------------------------------------
// Call Logs Endpoint for Mobile Clients with Date Filtering
// ----------------------------------------------------
app.get('/api/call-logs/:userId', async (req, res) => {
    const { userId } = req.params;
    const { startDate, endDate } = req.query;

    try {
        let query = `
            SELECT call_sid, from_number, to_number, call_status, direction, line_type, carrier, risk_label, voicemail_url, voicemail_text, created_at 
            FROM call_logs 
            WHERE user_id = $1
        `;
        
        let queryParams = [userId];

        // If a date range is provided from the app (Today, Last 7 Days, Last 30 Days)
        if (startDate && endDate) {
            query += ` AND created_at >= $2::date AND created_at < ($3::date + INTERVAL '1 day')`;
            queryParams.push(startDate, endDate);
        }

        query += ` ORDER BY created_at DESC LIMIT 100`;

        const result = await pool.query(query, queryParams);
        res.json({ success: true, callLogs: result.rows });

    } catch (err) {
        console.error('Error fetching call logs:', err);
        res.status(500).json({ success: false, error: 'Server error fetching call logs.' });
    }
});


// ----------------------------------------------------
// Multi-Guardian Scheduled Daily Report Sweep (Runs every hour)
// ----------------------------------------------------
cron.schedule('0 * * * *', async () => {
    try {
        const now = new Date();
        const currentHourStr = String(now.getHours()).padStart(2, '0') + ':00';

        console.log(`[Cron Job] Checking guardian report schedules matching hour: ${currentHourStr}`);

        // Fetch each guardian setting row matching current hour
        const guardiansQuery = `
            SELECT 
                grs.owner_id,
                grs.guardian_id,
                grs.guardian_phone
            FROM guardian_report_settings grs
            JOIN users u ON grs.owner_id = u.id
            WHERE u.is_active = true 
              AND grs.daily_report_enabled = true 
              AND grs.report_time LIKE $1
        `;

        const guardiansResult = await pool.query(guardiansQuery, [`${currentHourStr.split(':')[0]}:%`]);

        for (const guardian of guardiansResult.rows) {
            const { owner_id, guardian_phone } = guardian;

            // Query call statistics for this owner from the last 24 hours
            const summaryQuery = `
                SELECT 
                    COUNT(*) AS total_calls,
                    SUM(CASE WHEN risk_label LIKE '%VoIP%' OR risk_label LIKE '%High Risk%' THEN 1 ELSE 0 END) AS high_risk_count,
                    SUM(CASE WHEN call_status = 'voicemail' THEN 1 ELSE 0 END) AS voicemail_count
                FROM call_logs 
                WHERE user_id = $1 
                  AND created_at >= NOW() - INTERVAL '24 hours';
            `;

            const statsResult = await pool.query(summaryQuery, [owner_id]);
            const stats = statsResult.rows[0];
            const totalCalls = parseInt(stats.total_calls, 10) || 0;

            if (totalCalls > 0) {
                const reportMessage = `📊 Senior Scam Shield Daily Summary:\n` +
                    `- Total Calls Intercepted: ${totalCalls}\n` +
                    `- High-Risk / VoIP Calls: ${stats.high_risk_count}\n` +
                    `- Voicemails Recorded: ${stats.voicemail_count}\n` +
                    `Check your app for full details.`;

                await sendGuardianSMS(guardian_phone, reportMessage);
                console.log(`[Report Sent] To guardian phone ${guardian_phone} for owner ${owner_id}`);
            }
        }
    } catch (err) {
        console.error('[Cron Job Error] Failed to process guardian scheduled reports:', err);
    }
});

// ----------------------------------------------------
// Endpoint to Upsert User Settings
// ----------------------------------------------------
app.post('/api/user/settings', async (req, res) => {
    const { userId, reportTime, isCallShieldEnabled, messageName } = req.body;

    if (!userId) {
        return res.status(400).json({ success: false, error: 'User ID is required.' });
    }

    try {
        const upsertQuery = `
            INSERT INTO user_settings (user_id, report_time, is_call_shield_enabled, message_name, updated_at)
            VALUES ($1, COALESCE($2, '20:00'), COALESCE($3, true), $4, NOW())
            ON CONFLICT (user_id) 
            DO UPDATE SET 
                report_time = COALESCE(EXCLUDED.report_time, user_settings.report_time),
                is_call_shield_enabled = COALESCE(EXCLUDED.is_call_shield_enabled, user_settings.is_call_shield_enabled),
                message_name = COALESCE(EXCLUDED.message_name, user_settings.message_name),
                updated_at = NOW();
        `;

        await pool.query(upsertQuery, [userId, reportTime, isCallShieldEnabled, messageName]);
        res.json({ success: true, message: 'User settings updated successfully.' });
    } catch (err) {
        console.error('Error updating user settings:', err);
        res.status(500).json({ success: false, error: 'Server error updating settings.' });
    }
});

const twilio = require('twilio');
const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

/**
 * 1. Get stats for all regional hubs (Total vs Unassigned counts per hub)
 */
app.get('/api/admin/regional-hubs-stats', async (req, res) => {
    try {
        const query = `
            SELECT 
                h.id AS hub_id,
                h.hub_code,
                h.hub_name,
                STRING_AGG(ac.area_code, ', ') AS area_codes,
                COUNT(n.id) FILTER (WHERE n.user_id IS NULL OR n.status = 'unassigned') AS unassigned_count,
                COUNT(n.id) AS total_count
            FROM regional_hubs h
            LEFT JOIN hub_area_codes ac ON h.id = ac.hub_id
            LEFT JOIN twilio_numbers n ON h.id = n.hub_id AND n.is_active = true
            WHERE h.is_active = true
            GROUP BY h.id, h.hub_code, h.hub_name
            ORDER BY h.id ASC;
        `;
        const result = await pool.query(query);
        res.json({ success: true, hubs: result.rows });
    } catch (err) {
        console.error('❌ Error fetching regional hub stats:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

/**
 * 2. Bulk provision numbers for a specific regional hub
 */
app.post('/api/admin/provision-hub-numbers', async (req, res) => {
    let { hubId, count = 1 } = req.body;
    count = parseInt(count, 10) || 1;

    try {
        // Step A: Find available area codes mapped to this hub
        const acQuery = `SELECT area_code FROM hub_area_codes WHERE hub_id = $1;`;
        const acResult = await pool.query(acQuery, [hubId]);

        if (acResult.rows.length === 0) {
            return res.status(400).json({ success: false, error: 'No area codes configured for this hub.' });
        }

        // Pick the first area code associated with the hub (or rotate if you prefer)
        const targetAreaCode = acResult.rows[0].area_code;
        console.log(`🔍 Searching for ${count} numbers in area code ${targetAreaCode} for hub ID ${hubId}...`);

        // Step B: Search available numbers from Twilio
        const availableNumbers = await client.availablePhoneNumbers('US')
            .local
            .list({ areaCode: targetAreaCode, limit: count });

        if (availableNumbers.length === 0) {
            return res.status(404).json({ success: false, error: `No Twilio numbers available in area code ${targetAreaCode}.` });
        }

        let addedCount = 0;
        const newlyAdded = [];

        for (const avail of availableNumbers) {
            try {
                // Buy from Twilio and link to your webhook
                const purchasedNumber = await client.incomingPhoneNumbers.create({
                    phoneNumber: avail.phoneNumber,
                    voiceUrl: 'https://mobilecallshield-backend.onrender.com/api/twilio/voice',
                    voiceMethod: 'POST'
                });

                // Insert into database with explicit hub reference
                const insertQuery = `
                    INSERT INTO twilio_numbers (phone_number, twilio_sid, hub_id, user_id, status, is_active)
                    VALUES ($1, $2, $3, NULL, 'unassigned', true)
                    RETURNING id, phone_number, hub_id, status;
                `;
                const dbResult = await pool.query(insertQuery, [purchasedNumber.phoneNumber, purchasedNumber.sid, hubId]);
                newlyAdded.push(dbResult.rows[0]);
                addedCount++;
            } catch (purchaseErr) {
                console.error(`⚠️ Failed to buy ${avail.phoneNumber}:`, purchaseErr.message);
            }
        }

        res.json({
            success: true,
            message: `Successfully provisioned ${addedCount} numbers to hub!`,
            numbers: newlyAdded
        });

    } catch (err) {
        console.error('❌ Error provisioning hub numbers:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

/**
 * 3. Background Cron Job: Check regional inventories and send alerts if any hub < 5
 */
async function checkAllHubsInventoryAndAlert() {
    try {
        const query = `
            SELECT 
                h.hub_code,
                h.hub_name,
                COUNT(n.id) FILTER (WHERE n.user_id IS NULL OR n.status = 'unassigned') AS unassigned_count
            FROM regional_hubs h
            LEFT JOIN twilio_numbers n ON h.id = n.hub_id AND n.is_active = true
            WHERE h.is_active = true
            GROUP BY h.id, h.hub_code, h.hub_name;
        `;
        const result = await pool.query(query);

        for (const hub of result.rows) {
            const count = parseInt(hub.unassigned_count, 10);
            console.log(`📊 Hub [${hub.hub_name}] unassigned buffer: ${count}`);

            if (count < 5) {
                const alertMessage = `⚠️ Low Inventory Alert: Regional Hub "${hub.hub_name}" is down to ${count} unassigned numbers. Restock recommended!`;
                
                await client.messages.create({
                    body: alertMessage,
                    from: process.env.TWILIO_ADMIN_SENDER_NUMBER,
                    to: process.env.ADMIN_PHONE_NUMBER
                });
                console.log(`🚨 Sent low-inventory SMS alert for hub: ${hub.hub_code}`);
            }
        }
    } catch (err) {
        console.error('❌ Error checking hub inventories:', err);
    }
}


// ----------------------------------------------------
// Server Listen
// ----------------------------------------------------
app.listen(PORT, () => {
    console.log(`Mobile Call Shield server running on port ${PORT}`);
});