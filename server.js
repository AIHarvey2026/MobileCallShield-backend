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
const cron = require('node-cron');
const { Readable } = require('stream');

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
const TWILIO_NUMBER = process.env.TWILIO_PHONE_NUMBER || '+18775217775';
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

// --- Unified Twilio SMS Helper Function (Supports User's Assigned Number) ---
async function sendGuardianSMS(toPhoneNumber, messageBody, assignedTwilioNumber = null) {
    if (!toPhoneNumber) return;
    try {
        const senderNumber = assignedTwilioNumber || process.env.TWILIO_PHONE_NUMBER || TWILIO_NUMBER;

        await twilioClient.messages.create({
            body: messageBody,
            from: senderNumber,
            to: toPhoneNumber
        });
        console.log(`[SMS Alert Sent] To: ${toPhoneNumber} from ${senderNumber}`);
    } catch (err) {
        console.error('[SMS Alert Error] Failed to send guardian SMS:', err);
    }
}

// --- Nodemailer Transporter for Custom Domain (support@mobilecallshield.com) ---
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '465', 10),
    secure: parseInt(process.env.SMTP_PORT || '465', 10) === 465,
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

async function resolveActorRole(dbClient, dependentUserId, actorUserId) {
    const parsedDependentId = parseInt(dependentUserId, 10);
    const parsedActorId = parseInt(actorUserId, 10);

    if (isNaN(parsedActorId) || parsedActorId === parsedDependentId) {
        return {
            actorUserId: parsedDependentId,
            role: 'protectee',
            isPrimary: true,
            isGuardian: true
        };
    }

    const userRes = await dbClient.query(
        'SELECT primary_guardian_id FROM users WHERE id = $1',
        [parsedDependentId]
    );
    const primaryGuardianId = userRes.rows[0]?.primary_guardian_id;

    const guardianRes = await dbClient.query(
        `SELECT permission_level
         FROM account_guardians
         WHERE dependent_user_id = $1
           AND guardian_user_id = $2
           AND is_active = true
         LIMIT 1`,
        [parsedDependentId, parsedActorId]
    );

    if (guardianRes.rowCount > 0) {
        const perm = String(guardianRes.rows[0].permission_level || '').toLowerCase();
        const isPrimary = perm === 'primary' || Number(primaryGuardianId) === parsedActorId;
        return {
            actorUserId: parsedActorId,
            role: isPrimary ? 'primary_guardian' : 'co_guardian',
            isPrimary,
            isGuardian: true
        };
    }

    if (Number(primaryGuardianId) === parsedActorId) {
        return {
            actorUserId: parsedActorId,
            role: 'primary_guardian',
            isPrimary: true,
            isGuardian: true
        };
    }

    return {
        actorUserId: parsedActorId,
        role: 'system',
        isPrimary: false,
        isGuardian: false
    };
}

async function logAuditEvent(dbClient, { dependentUserId, performedByUserId, role, actionType, changes }) {
    try {
        await dbClient.query(
            `INSERT INTO audit_logs (dependent_user_id, performed_by_user_id, performed_by_role, action_type, changes_json, created_at)
             VALUES ($1, $2, $3, $4, $5::jsonb, NOW())`,
            [
                dependentUserId,
                performedByUserId || null,
                role || 'system',
                actionType,
                JSON.stringify(changes || {})
            ]
        );
    } catch (err) {
        console.error('[Audit Log Error] Failed to record audit event:', err);
    }
}

// -----------------------------------------------------------------------------------------
// 4. JWT Authentication Middleware
// -----------------------------------------------------------------------------------------
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

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

        const threshold = 5;

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
    const {
        name,
        phoneNumber,
        email,
        password,
        pin,
        passcode,
        messageName,
        securityQuestion,
        securityAnswer,
        accountType
    } = req.body;

    // 1. Strict Validation for Required Fields
    if (!password || !email || !pin || !accountType) {
        return res.status(400).json({
            error: 'Email, password, PIN, and accountType (protectee, guardian, or solo) are required.'
        });
    }

    const allowedAccountTypes = ['protectee', 'guardian', 'solo'];
    const normalizedAccountType = String(accountType).trim().toLowerCase();

    if (!allowedAccountTypes.includes(normalizedAccountType)) {
        return res.status(400).json({
            error: "Invalid accountType. Must be 'protectee', 'guardian', or 'solo'."
        });
    }

    const realPhone = (phoneNumber && phoneNumber !== '+10000000000') ? phoneNumber : null;
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        // Sanitize greeting name if provided
        let sanitizedMessageName = null;
        try {
            sanitizedMessageName = sanitizeAndValidateMessageName(messageName);
        } catch (validationErr) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: validationErr.message });
        }

        // 2. Duplicate Account Check (Owner Phone or Email)
        const existingUser = await client.query(
            'SELECT id FROM users WHERE ($1::text IS NOT NULL AND owner_phone = $1) OR email = $2',
            [realPhone, email]
        );

        if (existingUser.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(409).json({ error: 'An account with this phone number or email already exists.' });
        }

        const userPasscode = passcode ? passcode.trim().toLowerCase() : '1234';
        const passwordHash = await bcrypt.hash(String(password), 10);

        const finalQuestion = securityQuestion && securityQuestion.trim() !== ''
            ? securityQuestion.trim()
            : "What was the name of your first pet?";

        const finalAnswer = securityAnswer && securityAnswer.trim() !== ''
            ? securityAnswer.trim().toLowerCase()
            : "fluffy";

        const trialEnd = new Date();
        trialEnd.setDate(trialEnd.getDate() + 14);

        // 3. Insert New User
        const newUser = await client.query(
            `INSERT INTO users (
                user_name, owner_phone, email, password, pin, passcode, 
                message_name, security_question, security_answer, 
                subscription_status, trial_ends_at, created_at
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'trialing', $10, NOW())
             RETURNING id, user_name, owner_phone, email, passcode, message_name, security_question, subscription_status`,
            [name || email, realPhone, email, passwordHash, pin, userPasscode, sanitizedMessageName, finalQuestion, finalAnswer, trialEnd]
        );

        const newUserId = newUser.rows[0].id;

        // 4. Regional Hub Phone Number Assignment Logic
        let assignedPhoneNumber = null;
        let phoneRow = null;

        if (realPhone) {
            const cleanDigits = realPhone.replace(/\D/g, '');
            const userAreaCode = cleanDigits.length >= 10 ? cleanDigits.slice(-10, -7) : null;

            if (userAreaCode) {
                const hubMatchQuery = await client.query(
                    `SELECT n.id, n.phone_number FROM twilio_numbers n
                     JOIN hub_area_codes ac ON n.hub_id = ac.hub_id
                     WHERE ac.area_code = $1 AND (n.is_active = false OR n.user_id IS NULL)
                     ORDER BY n.id ASC LIMIT 1 FOR UPDATE`,
                    [userAreaCode]
                );

                if (hubMatchQuery.rows.length > 0) {
                    phoneRow = hubMatchQuery.rows[0];
                }
            }
        }

        if (!phoneRow) {
            const fallbackQuery = await client.query(
                `SELECT id, phone_number FROM twilio_numbers
                 WHERE is_active = false OR user_id IS NULL
                 ORDER BY id ASC LIMIT 1 FOR UPDATE`
            );
            if (fallbackQuery.rows.length > 0) {
                phoneRow = fallbackQuery.rows[0];
            }
        }

        if (phoneRow) {
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

        // 5. Audit Logging for Account Registration
        if (typeof logAuditEvent === 'function') {
            await logAuditEvent(client, {
                dependentUserId: newUserId,
                performedByUserId: newUserId,
                role: normalizedAccountType === 'protectee' ? 'protectee' : normalizedAccountType,
                actionType: 'ACCOUNT_REGISTERED',
                changes: {
                    accountType: normalizedAccountType,
                    assignedTwilioNumber: assignedPhoneNumber
                }
            });
        }

        await client.query('COMMIT');

        // 6. Return Success Response & Auth Token
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
                accountType: normalizedAccountType,
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

//Login
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

// Get the latest MCS version
app.get('/api/app-version/latest', async (req, res) => {
    try {
        const platform = (req.query.platform || 'all').trim().toLowerCase();

        const query = `
            SELECT id, platform, version_code, build_number, release_notes, is_latest, is_required, released_at
            FROM app_versions
            WHERE ($1 = 'all' OR platform = $1 OR platform = 'all')
            ORDER BY is_latest DESC, build_number DESC, id DESC
            LIMIT 1;
        `;

        const result = await pool.query(query, [platform]);

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, error: 'No version record found.' });
        }

        res.json({
            success: true,
            version: result.rows[0]
        });
    } catch (err) {
        console.error('Error fetching latest app version:', err);
        res.status(500).json({ success: false, error: 'Server error fetching latest app version.' });
    }
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

//Deactivate user (No Primary Guardian, user pin, Primary Guardian (primary Guardian pin))

app.post('/api/user/deactivate', async (req, res) => {
    const { userId, guardianPin, actorUserId } = req.body;
    const targetUserId = parseInt(userId, 10);
    const effectiveActorId = parseInt(actorUserId || req.user?.id || targetUserId, 10);

    if (!targetUserId || isNaN(targetUserId)) {
        return res.status(400).json({ error: 'Missing userId' });
    }

    const dbClient = await pool.connect();
    try {
        const userResult = await dbClient.query(
            `SELECT u.*,
                    EXISTS (
                        SELECT 1
                        FROM account_guardians ag
                        WHERE ag.dependent_user_id = u.id
                          AND ag.is_active = true
                          AND ag.permission_level = 'primary'
                    ) AS has_primary_guardian_row
             FROM users u
             WHERE u.id = $1`,
            [targetUserId]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const user = userResult.rows[0];
        const hasPrimaryGuardian = Boolean(
            user.primary_guardian_id || user.has_primary_guardian_row
        );
        const actor = await resolveActorRole(dbClient, targetUserId, effectiveActorId);

        if (hasPrimaryGuardian) {
            if (!actor.isPrimary) {
                await logAuditEvent(dbClient, {
                    dependentUserId: targetUserId,
                    performedByUserId: effectiveActorId,
                    role: actor.role,
                    actionType: 'DENIED_DEACTIVATE_ACCOUNT',
                    changes: {
                        hasPrimaryGuardian: true,
                        reason: 'Only Primary Guardian can deactivate account when one is assigned'
                    }
                });
                return res.status(403).json({
                    success: false,
                    error: 'Only the Primary Guardian can deactivate this account.'
                });
            }

            const primaryId = user.primary_guardian_id || effectiveActorId;
            const guardianUserRes = await dbClient.query(
                `SELECT pin, guardian_code FROM users WHERE id = $1`,
                [primaryId]
            );
            const expectedPin =
                guardianUserRes.rows[0]?.guardian_code ||
                guardianUserRes.rows[0]?.pin ||
                user.guardian_code ||
                user.pin;

            if (!guardianPin) {
                return res.status(401).json({ error: 'Primary Guardian PIN required' });
            }

            if (expectedPin && String(guardianPin).trim() !== String(expectedPin).trim()) {
                await logAuditEvent(dbClient, {
                    dependentUserId: targetUserId,
                    performedByUserId: effectiveActorId,
                    role: actor.role,
                    actionType: 'DENIED_DEACTIVATE_ACCOUNT',
                    changes: { reason: 'Incorrect Primary Guardian PIN' }
                });
                return res.status(401).json({ error: 'Incorrect Guardian PIN' });
            }
        } else {
            const ownerPin = user.guardian_code || user.pin;
            if (guardianPin && ownerPin && String(guardianPin).trim() !== String(ownerPin).trim()) {
                await logAuditEvent(dbClient, {
                    dependentUserId: targetUserId,
                    performedByUserId: effectiveActorId,
                    role: actor.role,
                    actionType: 'DENIED_DEACTIVATE_ACCOUNT',
                    changes: { reason: 'Incorrect PIN' }
                });
                return res.status(401).json({ error: 'Incorrect PIN' });
            }
        }

        await dbClient.query('UPDATE users SET is_active = false WHERE id = $1', [targetUserId]);

        await logAuditEvent(dbClient, {
            dependentUserId: targetUserId,
            performedByUserId: effectiveActorId,
            role: hasPrimaryGuardian ? 'primary_guardian' : actor.role,
            actionType: 'DEACTIVATE_ACCOUNT',
            changes: { isActive: false, hasPrimaryGuardian }
        });

        res.json({
            success: true,
            message: 'Account successfully deactivated and subscription stopped.'
        });
    } catch (error) {
        console.error('Deactivation error:', error);
        res.status(500).json({ error: 'Internal server error during deactivation' });
    } finally {
        dbClient.release();
    }
});
app.put('/api/user/toggle-shield', async (req, res) => {
    const { userId, isEnabled, pin, actorUserId } = req.body;
    const targetUserId = parseInt(userId, 10);
    const effectiveActorId = actorUserId || req.user?.id || targetUserId;

    if (!targetUserId || isNaN(targetUserId)) {
        return res.status(400).json({ error: 'User ID is required.' });
    }

    const dbClient = await pool.connect();
    try {
        const userResult = await dbClient.query(
            `SELECT u.pin,
                    u.guardian_code,
                    u.is_call_shield_enabled,
                    u.primary_guardian_id,
                    EXISTS (
                        SELECT 1
                        FROM account_guardians ag
                        WHERE ag.dependent_user_id = u.id
                          AND ag.is_active = true
                          AND ag.permission_level = 'primary'
                    ) AS has_primary_guardian_row
             FROM users u
             WHERE u.id = $1`,
            [targetUserId]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }

        const userRow = userResult.rows[0];
        const hasPrimaryGuardian = Boolean(
            userRow.primary_guardian_id || userRow.has_primary_guardian_row
        );

        const actor = await resolveActorRole(dbClient, targetUserId, effectiveActorId);

        if (isEnabled === false) {
            // If a primary guardian is assigned, only the primary guardian can turn off Call Shield
            if (hasPrimaryGuardian && !actor.isPrimary) {
                await logAuditEvent(dbClient, {
                    dependentUserId: targetUserId,
                    performedByUserId: effectiveActorId,
                    role: actor.role,
                    actionType: 'DENIED_TOGGLE_SHIELD',
                    changes: {
                        requestedEnabled: false,
                        hasPrimaryGuardian: true,
                        reason: 'Primary guardian required to turn off Call Shield'
                    }
                });
                return res.status(403).json({
                    success: false,
                    error: 'Primary Guardian is required to turn off Call Shield.'
                });
            }

            // If no primary guardian is assigned (or when a PIN is provided), validate PIN
            const dbPin = userRow.guardian_code || userRow.pin || '1234';
            if (pin && String(pin).trim() !== String(dbPin).trim()) {
                return res.status(401).json({ success: false, error: 'Incorrect PIN.' });
            }
        }

        await dbClient.query(
            'UPDATE users SET is_call_shield_enabled = $1 WHERE id = $2',
            [Boolean(isEnabled), targetUserId]
        );

        await logAuditEvent(dbClient, {
            dependentUserId: targetUserId,
            performedByUserId: effectiveActorId,
            role: actor.role,
            actionType: isEnabled ? 'ENABLE_SHIELD' : 'DISABLE_SHIELD',
            changes: {
                previousEnabled: userRow.is_call_shield_enabled,
                isCallShieldEnabled: Boolean(isEnabled),
                hasPrimaryGuardian
            }
        });

        res.json({ success: true, message: `Shield status updated to ${Boolean(isEnabled)}` });
    } catch (err) {
        console.error('Error toggling shield:', err);
        res.status(500).json({ error: 'Server error updating shield status.' });
    } finally {
        dbClient.release();
    }
});

app.post('/api/user/resume-shield', async (req, res) => {
    const { userId, resumedByUserId, actorUserId } = req.body;
    const parsedUserId = parseInt(userId, 10);
    const effectiveActorId = resumedByUserId || actorUserId || req.user?.id || parsedUserId;

    if (isNaN(parsedUserId)) {
        return res.status(400).json({ success: false, error: 'Invalid userId' });
    }

    const dbClient = await pool.connect();
    try {
        const actor = await resolveActorRole(dbClient, parsedUserId, effectiveActorId);
        const isAuthorized = actor.role === 'protectee' || actor.isGuardian;

        if (!isAuthorized) {
            await logAuditEvent(dbClient, {
                dependentUserId: parsedUserId,
                performedByUserId: effectiveActorId,
                role: actor.role,
                actionType: 'DENIED_RESUME_SHIELD',
                changes: { reason: 'Unauthorized actor attempted to resume shield' }
            });
            return res.status(403).json({
                success: false,
                error: 'Unauthorized: You are not assigned as a guardian for this account'
            });
        }

        const existing = await dbClient.query(
            `SELECT pause_mode, pause_until FROM users WHERE id = $1`,
            [parsedUserId]
        );

        if (existing.rowCount === 0) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }

        await dbClient.query(
            `UPDATE users
             SET pause_mode = NULL, pause_until = NULL
             WHERE id = $1`,
            [parsedUserId]
        );

        await logAuditEvent(dbClient, {
            dependentUserId: parsedUserId,
            performedByUserId: effectiveActorId,
            role: actor.role,
            actionType: 'RESUME_SHIELD',
            changes: {
                previousPauseMode: existing.rows[0].pause_mode,
                previousPauseUntil: existing.rows[0].pause_until,
                pauseMode: null,
                pauseUntil: null
            }
        });

        return res.json({
            success: true,
            message: 'Shield protection successfully resumed',
            userId: parsedUserId,
            pauseMode: null,
            pauseUntil: null
        });
    } catch (error) {
        console.error('[Resume Shield Error]:', error);
        return res.status(500).json({ success: false, error: error.message });
    } finally {
        dbClient.release();
    }
});

app.post('/api/user/pause-shield', async (req, res) => {
    const { userId, mode, durationHours, untilTomorrowMorning, vacationDays, endDate, actorUserId } = req.body;
    const parsedUserId = parseInt(userId, 10);
    const effectiveActorId = actorUserId || req.user?.id || parsedUserId;

    if (isNaN(parsedUserId) || !['dnd', 'vacation'].includes(mode)) {
        return res.status(400).json({ success: false, error: 'Valid userId and mode (dnd or vacation) are required' });
    }

    const dbClient = await pool.connect();
    try {
        const actor = await resolveActorRole(dbClient, parsedUserId, effectiveActorId);
        const canPauseShield = actor.role === 'protectee' || actor.isPrimary;

        if (!canPauseShield) {
            await logAuditEvent(dbClient, {
                dependentUserId: parsedUserId,
                performedByUserId: effectiveActorId,
                role: actor.role,
                actionType: 'DENIED_PAUSE_SHIELD',
                changes: { mode, reason: 'Only primary guardian or account owner can pause shield' }
            });
            return res.status(403).json({
                success: false,
                error: 'Only the Primary Guardian can pause Call Shield.'
            });
        }

        let pauseUntilDate = null;
        const now = new Date();

        if (mode === 'dnd') {
            if (untilTomorrowMorning) {
                pauseUntilDate = getNext8AmCentralDate(now);
            } else {
                const hours = parseInt(durationHours, 10);
                if (![1, 2, 4].includes(hours)) {
                    return res.status(400).json({ success: false, error: 'DND durationHours must be 1, 2, or 4' });
                }
                pauseUntilDate = new Date(now.getTime() + hours * 60 * 60 * 1000);
            }
        } else if (mode === 'vacation') {
            if (endDate) {
                pauseUntilDate = new Date(endDate);
            } else {
                const days = parseInt(vacationDays, 10);
                if (isNaN(days) || days < 1 || days > 30) {
                    return res.status(400).json({ success: false, error: 'Vacation days must be between 1 and 30' });
                }
                pauseUntilDate = new Date(now.getTime() + days * 24 * 60 * 60 * 1000);
            }
        }

        if (!pauseUntilDate || isNaN(pauseUntilDate.getTime()) || pauseUntilDate <= now) {
            return res.status(400).json({ success: false, error: 'Invalid expiration timestamp' });
        }

        const result = await dbClient.query(
            `UPDATE users
             SET pause_mode = $1, pause_until = $2
             WHERE id = $3
             RETURNING id, pause_mode, pause_until`,
            [mode, pauseUntilDate.toISOString(), parsedUserId]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }

        await logAuditEvent(dbClient, {
            dependentUserId: parsedUserId,
            performedByUserId: effectiveActorId,
            role: actor.role,
            actionType: 'PAUSE_SHIELD',
            changes: {
                pauseMode: result.rows[0].pause_mode,
                pauseUntil: result.rows[0].pause_until
            }
        });

        return res.json({
            success: true,
            pauseMode: result.rows[0].pause_mode,
            pauseUntil: result.rows[0].pause_until
        });
    } catch (error) {
        console.error('Error setting pause shield:', error);
        return res.status(500).json({ success: false, error: error.message });
    } finally {
        dbClient.release();
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
// Example: GET /api/guardians/my-protectees/:guardianUserId
app.get('/api/guardians/my-protectees/:guardianUserId', async (req, res) => {
    const guardianUserId = parseInt(req.params.guardianUserId, 10);
    if (!guardianUserId || isNaN(guardianUserId)) {
        return res.status(400).json({ success: false, error: 'Valid guardianUserId is required.' });
    }

    try {
        const result = await pool.query(
            `SELECT ag.id AS relationship_id,
                    ag.dependent_user_id,
                    u.user_name AS name,
                    u.owner_phone AS phone_number,
                    ag.permission_level AS relationship,
                    ag.created_at
             FROM account_guardians ag
             JOIN users u ON ag.dependent_user_id = u.id
             WHERE ag.guardian_user_id = $1
             ORDER BY u.user_name ASC, ag.id ASC`,
            [guardianUserId]
        );

        return res.json({
            success: true,
            protectees: result.rows
        });
    } catch (err) {
        console.error('Error fetching protectees for guardian:', err);
        return res.status(500).json({ success: false, error: 'Server error fetching protectees.' });
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
            phone: row.phone_number,
            phone_number: row.phone_number,
            is_guardian: true,
            is_primary: row.is_primary || false
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
                let rawPhone = "";
                if (Array.isArray(contact.phone_numbers) && contact.phone_numbers.length > 0) {
                    rawPhone = contact.phone_numbers[0];
                } else if (Array.isArray(contact.phoneNumbers) && contact.phoneNumbers.length > 0) {
                    const entry = contact.phoneNumbers[0];
                    rawPhone = typeof entry === 'string' ? entry : (entry.number || entry.digits || '');
                } else if (contact.phone_number) {
                    rawPhone = contact.phone_number;
                }

                const phone = toE164(rawPhone);
                if (!phone) continue;

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

// 2. Update Primary Guardian Designation
app.patch('/api/trusted-contacts/:contactId/primary', async (req, res) => {
    const { contactId } = req.params;
    const { userId, isPrimary, actorUserId } = req.body;
    const targetUserId = parseInt(userId, 10);
    const effectiveActorId = actorUserId || req.user?.id || targetUserId;

    const dbClient = await pool.connect();
    try {
        const actor = await resolveActorRole(dbClient, targetUserId, effectiveActorId);

        if (actor.role === 'co_guardian') {
            await logAuditEvent(dbClient, {
                dependentUserId: targetUserId,
                performedByUserId: effectiveActorId,
                role: actor.role,
                actionType: 'DENIED_UPDATE_PRIMARY_GUARDIAN',
                changes: { contactId, reason: 'Only primary guardian or account owner can change primary status' }
            });
            return res.status(403).json({
                success: false,
                error: 'Only the Primary Guardian or account owner can alter Primary status.'
            });
        }

        const contactRes = await dbClient.query(
            `SELECT phone_number FROM trusted_contacts WHERE id = $1 AND user_id = $2`,
            [contactId, targetUserId]
        );

        if (contactRes.rowCount === 0) {
            return res.status(404).json({ success: false, error: 'Contact not found.' });
        }

        const phone = contactRes.rows[0].phone_number;
        const guardianUserRes = await dbClient.query(
            `SELECT id FROM users WHERE phone_number = $1 OR owner_phone = $1 LIMIT 1`,
            [phone]
        );

        if (guardianUserRes.rowCount > 0) {
            const guardianUserId = guardianUserRes.rows[0].id;
            if (isPrimary) {
                await dbClient.query(`UPDATE users SET primary_guardian_id = $1 WHERE id = $2`, [guardianUserId, targetUserId]);
                await dbClient.query(
                    `UPDATE account_guardians SET permission_level = 'primary' WHERE dependent_user_id = $1 AND guardian_user_id = $2`,
                    [targetUserId, guardianUserId]
                );
            }
        }

        await logAuditEvent(dbClient, {
            dependentUserId: targetUserId,
            performedByUserId: effectiveActorId,
            role: actor.role,
            actionType: 'UPDATE_PRIMARY_GUARDIAN',
            changes: { contactId, isPrimary: Boolean(isPrimary) }
        });

        return res.json({ success: true, message: 'Primary guardian status updated.' });
    } catch (err) {
        console.error('Error updating primary status:', err);
        return res.status(500).json({ success: false, error: 'Failed to update primary status.' });
    } finally {
        dbClient.release();
    }
});

// Update for trusted_contacts primary management
app.put('/api/trusted_contacts/:id', async (req, res) => {
    const contactId = req.params.id;
    const { name, phone_number, relationship, is_guardian, is_primary } = req.body;
    let dbClient = null;

    try {
        dbClient = await pool.connect();

        if (is_primary) {
            const contactCheck = await dbClient.query(`SELECT user_id FROM trusted_contacts WHERE id = $1`, [contactId]);
            if (contactCheck.rows.length > 0) {
                const userId = contactCheck.rows[0].user_id;
                await dbClient.query(
                    `UPDATE trusted_contacts SET is_primary = false WHERE user_id = $1 AND id != $2`,
                    [userId, contactId]
                );
            }
        }

        const updateQuery = await dbClient.query(
            `UPDATE trusted_contacts
             SET name = COALESCE($1, name),
                 phone_number = COALESCE($2, phone_number),
                 relationship = COALESCE($3, relationship),
                 is_guardian = COALESCE($4, is_guardian),
                 is_primary = COALESCE($5, is_primary),
                 updated_at = NOW()
             WHERE id = $6
             RETURNING *`,
            [name, phone_number, relationship, is_guardian, is_primary, contactId]
        );

        if (updateQuery.rows.length === 0) {
            return res.status(404).json({ error: 'Trusted contact not found' });
        }

        res.json({
            success: true,
            message: 'Contact updated successfully',
            contact: updateQuery.rows[0]
        });
    } catch (err) {
        console.error('[Update Trusted Contact Error]:', err);
        res.status(500).json({ error: 'Failed to update contact' });
    } finally {
        if (dbClient) {
            dbClient.release();
        }
    }
});

app.put('/api/user/update-pin', async (req, res) => {
    const { userId, newPin, pin, actorUserId } = req.body;
    const targetUserId = parseInt(userId || req.user?.id, 10);
    const effectiveActorId = parseInt(actorUserId || req.user?.id || targetUserId, 10);
    const pinToSave = newPin || pin;

    if (!targetUserId || isNaN(targetUserId) || !pinToSave) {
        return res.status(400).json({ success: false, error: 'User ID and new PIN are required.' });
    }

    const dbClient = await pool.connect();
    try {
        const actor = await resolveActorRole(dbClient, targetUserId, effectiveActorId);
        const isOwnAccount = effectiveActorId === targetUserId;
        const canUpdatePin = isOwnAccount || actor.isPrimary;

        if (!canUpdatePin) {
            await logAuditEvent(dbClient, {
                dependentUserId: targetUserId,
                performedByUserId: effectiveActorId,
                role: actor.role,
                actionType: 'DENIED_UPDATE_PIN',
                changes: { reason: 'Only account owner or primary guardian can update protectee PIN' }
            });
            return res.status(403).json({
                success: false,
                error: 'Only the Primary Guardian can update a protectee’s PIN.'
            });
        }

        const result = await dbClient.query(
            'UPDATE users SET pin = $1 WHERE id = $2 RETURNING id, pin',
            [String(pinToSave).trim(), targetUserId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, error: 'User not found.' });
        }

        await logAuditEvent(dbClient, {
            dependentUserId: targetUserId,
            performedByUserId: effectiveActorId,
            role: isOwnAccount ? 'protectee' : actor.role,
            actionType: 'UPDATE_GUARDIAN_PIN',
            changes: { updated: true, isOwnAccount }
        });

        res.json({
            success: true,
            message: 'PIN updated successfully!',
            pin: result.rows[0].pin
        });
    } catch (err) {
        console.error('Error updating PIN:', err);
        res.status(500).json({ success: false, error: 'Server error updating PIN.' });
    } finally {
        dbClient.release();
    }
});

app.post('/api/settings/update-passcode', async (req, res) => {
    const { userId, pin, currentPasscode, newPasscode, actorUserId } = req.body;
    const targetUserId = parseInt(userId, 10);
    const effectiveActorId = parseInt(actorUserId || req.user?.id || targetUserId, 10);

    if (!targetUserId || isNaN(targetUserId) || !pin || !newPasscode) {
        return res.status(400).json({ success: false, error: 'User ID, PIN, and new passcode are required.' });
    }

    const dbClient = await pool.connect();
    try {
        const actor = await resolveActorRole(dbClient, targetUserId, effectiveActorId);
        const isOwnAccount = effectiveActorId === targetUserId;
        const canUpdatePasscode = isOwnAccount || actor.isPrimary;

        if (!canUpdatePasscode) {
            await logAuditEvent(dbClient, {
                dependentUserId: targetUserId,
                performedByUserId: effectiveActorId,
                role: actor.role,
                actionType: 'DENIED_UPDATE_PASSCODE',
                changes: { reason: 'Only account owner or primary guardian can update protectee passcode' }
            });
            return res.status(403).json({
                success: false,
                error: 'Only the Primary Guardian can update a protectee’s passcode phrase.'
            });
        }

        const userResult = await dbClient.query('SELECT id, pin, passcode FROM users WHERE id = $1', [targetUserId]);

        if (userResult.rows.length === 0) {
            return res.status(404).json({ success: false, error: 'User not found.' });
        }

        const user = userResult.rows[0];

        if (String(user.pin).trim() !== String(pin).trim()) {
            return res.status(401).json({ success: false, error: 'Incorrect Owner PIN.' });
        }

        if (
            currentPasscode &&
            String(currentPasscode).trim().length > 0 &&
            String(user.passcode).trim().toLowerCase() !== String(currentPasscode).trim().toLowerCase()
        ) {
            return res.status(401).json({ success: false, error: 'Current passcode phrase does not match.' });
        }

        const result = await dbClient.query(
            'UPDATE users SET passcode = $1 WHERE id = $2 RETURNING id, passcode',
            [String(newPasscode).trim(), targetUserId]
        );

        await logAuditEvent(dbClient, {
            dependentUserId: targetUserId,
            performedByUserId: effectiveActorId,
            role: isOwnAccount ? 'protectee' : actor.role,
            actionType: 'UPDATE_PASSCODE_PHRASE',
            changes: { updated: true, isOwnAccount }
        });

        return res.json({
            success: true,
            message: 'Passcode phrase updated successfully!',
            passcode: result.rows[0].passcode
        });
    } catch (err) {
        console.error('Error updating passcode:', err);
        return res.status(500).json({ success: false, error: 'Server error updating passcode.' });
    } finally {
        dbClient.release();
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
// Twilio Voice Webhook Handler & Loop Prevention
// ----------------------------------------------------
app.post('/api/twilio/voice', async (req, res) => {
    const { CallSid, From, To, CallStatus, Direction } = req.body;
    const normalizedFrom = toE164(From) || From;
    const normalizedTo = toE164(To) || To;

    console.log(`[Twilio Webhook] Incoming call: SID=${CallSid}, From=${normalizedFrom}, To=${normalizedTo}, Status=${CallStatus}`);

    const dbClient = await pool.connect();
    try {
        const userQuery = await dbClient.query(
            `SELECT u.id AS user_id, u.user_name, u.owner_phone, u.is_call_shield_enabled, u.message_name
             FROM users u
             JOIN twilio_numbers tn ON u.id = tn.user_id
             WHERE tn.phone_number = $1 OR tn.phone_number = $2
             LIMIT 1`,
            [To, normalizedTo]
        );

        if (userQuery.rows.length === 0) {
            res.type('text/xml');
            return res.send(new VoiceResponse().say('This number is not active.').toString());
        }

        const user = userQuery.rows[0];
        const userId = user.user_id;
        const ownerLabel = user.message_name || user.user_name || 'the owner';

        // LOOP PREVENTION: Strict 10-Second Window for Rapid Carrier Bounces ONLY
        const rapidBounceCheck = await dbClient.query(
            `SELECT id FROM call_logs
             WHERE user_id = $1
               AND (from_number = $2 OR from_number = $3)
               AND created_at > NOW() - INTERVAL '10 seconds'`,
            [userId, From, normalizedFrom]
        );

        if (rapidBounceCheck.rows.length > 0) {
            console.log(`[Twilio Webhook] Rapid carrier bounce detected within 10 seconds for caller ${normalizedFrom}. Sending to voicemail to prevent loop.`);
            const twiml = new VoiceResponse();
            twiml.say('Please leave a message after the tone.');
            twiml.record({
                action: '/api/twilio/handle-voicemail',
                method: 'POST',
                maxLength: 60,
                transcribe: true,
                transcribeCallback: '/api/twilio/voicemail-transcription'
            });
            res.type('text/xml');
            return res.send(twiml.toString());
        }

        // FOLLOW-UP AFTER BRIDGED CALL: If this caller was just bridged to owner_phone and it bounced back unanswered
        const recentBridgeCheck = await dbClient.query(
            `SELECT id FROM call_logs
             WHERE user_id = $1
               AND (from_number = $2 OR from_number = $3)
               AND call_status = 'bridged_attempt'
               AND created_at > NOW() - INTERVAL '2 minutes'
             LIMIT 1`,
            [userId, From, normalizedFrom]
        );

        if (recentBridgeCheck.rows.length > 0) {
            await dbClient.query(
                `INSERT INTO call_logs (call_sid, user_id, from_number, to_number, call_status, direction, line_type, carrier, risk_label, created_at)
                 VALUES ($1, $2, $3, $4, 'voicemail', $5, 'PENDING', 'Pending Lookup', 'Evaluating...', NOW())
                 ON CONFLICT (call_sid) DO UPDATE
                 SET call_status = EXCLUDED.call_status`,
                [CallSid, userId, normalizedFrom, normalizedTo, Direction || 'inbound']
            );

            const twiml = new VoiceResponse();
            twiml.say(`${ownerLabel} is not available right now. You can leave a voicemail after the tone.`);
            twiml.record({
                action: '/api/twilio/handle-voicemail',
                method: 'POST',
                maxLength: 60,
                transcribe: true,
                transcribeCallback: '/api/twilio/voicemail-transcription'
            });
            res.type('text/xml');
            return res.send(twiml.toString());
        }

        await dbClient.query(
            `INSERT INTO call_logs (call_sid, user_id, from_number, to_number, call_status, direction, line_type, carrier, risk_label, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, 'PENDING', 'Pending Lookup', 'Evaluating...', NOW())
             ON CONFLICT (call_sid) DO UPDATE
             SET call_status = EXCLUDED.call_status`,
            [CallSid, userId, normalizedFrom, normalizedTo, CallStatus || 'ringing', Direction || 'inbound']
        );

        evaluateAndLogCallerAsync(CallSid, normalizedFrom, userId);

        const twiml = new VoiceResponse();

        // 1. IF CALL SHIELD IS DISABLED: Take a voicemail directly (Do NOT <Dial> owner_phone back)
        if (user.is_call_shield_enabled === false) {
            twiml.say('Call screening is paused. Please leave a message after the tone.');
            twiml.record({
                action: '/api/twilio/handle-voicemail',
                method: 'POST',
                maxLength: 60,
                transcribe: true,
                transcribeCallback: '/api/twilio/voicemail-transcription'
            });
            res.type('text/xml');
            return res.send(twiml.toString());
        }

        const contactCheck = await dbClient.query(
            `SELECT id FROM trusted_contacts
             WHERE user_id = $1 AND (phone_number = $2 OR phone_number = $3)`,
            [userId, From, normalizedFrom]
        );
        const isTrusted = contactCheck.rows.length > 0;

        // 2. IF TRUSTED CONTACT: Take a direct message without looping back to owner_phone
        if (isTrusted) {
            twiml.say(`You are verified as a trusted contact. ${ownerLabel} is unavailable to answer right now, so please leave a message after the tone.`);
            twiml.record({
                action: '/api/twilio/handle-voicemail',
                method: 'POST',
                maxLength: 60,
                transcribe: true,
                transcribeCallback: '/api/twilio/voicemail-transcription'
            });
        } else {
            // 3. UNTRUSTED / UNKNOWN CALLER: Interactive passcode gather
            const gather = twiml.gather({
                input: 'speech dtmf',
                action: '/api/twilio/verify-passcode',
                method: 'POST',
                timeout: 5,
                speechTimeout: 'auto'
            });

            gather.say(`This is Mobile Call Shield protecting ${ownerLabel}. Please state the passcode or enter it on your keypad. If you are a doctor or medical provider, please press 9 or say doctor.`);

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

        const normalizedPasscode = String(passcode).trim().toLowerCase();
        const isMatch = (digitsInput === normalizedPasscode) || (speechInput.includes(normalizedPasscode));

        if (digitsInput === '9' || speechInput.includes('doctor') || speechInput.includes('medical')) {
            if (CallSid) {
                await dbClient.query(
                    `UPDATE call_logs SET call_status = 'bridged_attempt' WHERE call_sid = $1`,
                    [CallSid]
                );
            }
            twiml.say('Connecting your urgent medical call.');
            if (ownerPhone) {
                twiml.dial(ownerPhone);
            } else {
                twiml.say('Owner phone not configured.');
            }
            res.type('text/xml');
            return res.send(twiml.toString());
        }

        if (isMatch) {
            if (CallSid) {
                await dbClient.query(
                    `UPDATE call_logs SET call_status = 'bridged_attempt' WHERE call_sid = $1`,
                    [CallSid]
                );
            }
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
    } catch (err) {
        console.error('[Verify Passcode DB Error]:', err);
        twiml.say('An application error has occurred.');
    } finally {
        if (dbClient) {
            dbClient.release();
        }
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

app.get('/api/voicemail/stream', async (req, res) => {
    const { url } = req.query;
    if (!url) return res.status(400).send('Recording URL is required');

    try {
        const credentials = Buffer.from(`${process.env.TWILIO_ACCOUNT_SID}:${process.env.TWILIO_AUTH_TOKEN}`).toString('base64');

        const response = await fetch(url, {
            headers: {
                'Authorization': `Basic ${credentials}`
            }
        });

        if (!response.ok) {
            console.error(`[Proxy Error] Twilio responded with status: ${response.status}`);
            return res.status(response.status).send('Failed to fetch media from Twilio');
        }

        res.setHeader('Content-Type', 'audio/mpeg');

        const nodeStream = Readable.fromWeb(response.body);
        nodeStream.pipe(res);
    } catch (err) {
        console.error('Error streaming voicemail:', err);
        res.status(500).send('Error loading audio file');
    }
});

// ----------------------------------------------------
// Call Logs Endpoint for Mobile Clients with Date Filtering
// ----------------------------------------------------
app.get('/api/call-logs/:userId', async (req, res) => {
    const { userId } = req.params;
    const { startDate, endDate, range, userIds, actorUserId, timeZone = 'America/Chicago' } = req.query;

    const primaryUserId = parseInt(userId, 10);
    const effectiveActorId = parseInt(actorUserId || req.user?.id || primaryUserId, 10);

    if (!primaryUserId || isNaN(primaryUserId)) {
        return res.status(400).json({ success: false, error: 'Valid userId is required.' });
    }

    let targetUserIds = [primaryUserId];
    if (typeof userIds === 'string' && userIds.trim().length > 0) {
        const parsed = userIds
            .split(',')
            .map((id) => parseInt(id.trim(), 10))
            .filter((id) => !isNaN(id));
        if (parsed.length > 0) {
            targetUserIds = [...new Set(parsed)];
        }
    } else if (Array.isArray(userIds) && userIds.length > 0) {
        const parsed = userIds
            .map((id) => parseInt(id, 10))
            .filter((id) => !isNaN(id));
        if (parsed.length > 0) {
            targetUserIds = [...new Set(parsed)];
        }
    }

    const dbClient = await pool.connect();
    try {
        for (const targetId of targetUserIds) {
            const actor = await resolveActorRole(dbClient, targetId, effectiveActorId);
            if (actor.role === 'unauthorized') {
                return res.status(403).json({
                    success: false,
                    error: `Unauthorized to view call logs for user ID ${targetId}.`
                });
            }
        }

        let query = `
            SELECT cl.call_sid,
                   cl.user_id,
                   u.user_name AS account_owner_name,
                   cl.from_number,
                   cl.to_number,
                   cl.call_status,
                   cl.direction,
                   cl.line_type,
                   cl.carrier,
                   cl.risk_label,
                   cl.voicemail_url,
                   cl.voicemail_text,
                   cl.created_at
            FROM call_logs cl
            JOIN users u ON cl.user_id = u.id
            WHERE cl.user_id = ANY($1::int[])
        `;

        const queryParams = [targetUserIds];
        let paramIndex = 2;

        if (range === 'today') {
            query += `
                AND cl.created_at >= ((NOW() AT TIME ZONE $${paramIndex})::date::timestamp AT TIME ZONE $${paramIndex})
                AND cl.created_at < (((NOW() AT TIME ZONE $${paramIndex})::date + INTERVAL '1 day')::timestamp AT TIME ZONE $${paramIndex})
            `;
            queryParams.push(timeZone);
            paramIndex += 1;
        } else if (range === '7d') {
            query += ` AND cl.created_at >= NOW() - INTERVAL '7 days'`;
        } else if (range === '30d') {
            query += ` AND cl.created_at >= NOW() - INTERVAL '30 days'`;
        } else if (startDate && endDate) {
            query += `
                AND cl.created_at >= ($${paramIndex}::date::timestamp AT TIME ZONE $${paramIndex + 2})
                AND cl.created_at < (($${paramIndex + 1}::date + INTERVAL '1 day')::timestamp AT TIME ZONE $${paramIndex + 2})
            `;
            queryParams.push(startDate, endDate, timeZone);
            paramIndex += 3;
        }

        query += ` ORDER BY cl.created_at DESC LIMIT 100`;

        const result = await dbClient.query(query, queryParams);
        res.json({ success: true, callLogs: result.rows });
    } catch (err) {
        console.error('Error fetching call logs:', err);
        res.status(500).json({ success: false, error: 'Server error fetching call logs.' });
    } finally {
        dbClient.release();
    }
});

// Audit Logs
app.get('/api/audit-logs/:dependentUserId', authenticateToken, async (req, res) => {
    const dependentUserId = parseInt(req.params.dependentUserId, 10);
    if (isNaN(dependentUserId)) {
        return res.status(400).json({ success: false, error: 'Invalid dependentUserId' });
    }

    try {
        const query = `
            SELECT
                al.id,
                al.dependent_user_id,
                al.performed_by_user_id,
                al.performed_by_role,
                al.action_type,
                al.changes_json,
                al.created_at,
                u.user_name AS actor_name,
                u.email AS actor_email
            FROM audit_logs al
            LEFT JOIN users u ON al.performed_by_user_id = u.id
            WHERE al.dependent_user_id = $1
            ORDER BY al.created_at DESC
            LIMIT 100
        `;
        const result = await pool.query(query, [dependentUserId]);
        res.json({ success: true, logs: result.rows });
    } catch (err) {
        console.error('Error fetching audit logs:', err);
        res.status(500).json({ success: false, error: 'Failed to fetch audit logs.' });
    }
});

// auditLogger.js
async function writeAuditLog(pool, {
  dependentUserId,
  performedByUserId = null,
  performedByRole = "owner",
  actionType,
  changes = {}
}) {
  if (!dependentUserId || !actionType) return;

  await pool.query(
    `
      INSERT INTO audit_logs (
        dependent_user_id,
        performed_by_user_id,
        performed_by_role,
        action_type,
        changes_json
      )
      VALUES ($1, $2, $3, $4, $5)
    `,
    [
      dependentUserId,
      performedByUserId,
      performedByRole,
      actionType,
      JSON.stringify(changes)
    ]
  );
}

module.exports = { writeAuditLog };

// ----------------------------------------------------
// Crons Schedule
// ----------------------------------------------------
const { fetchAndStoreTwilioCalls } = require('./services/twilioStatsService');
const { fetchAndStoreStrideStats } = require('./services/strideService');

// 1. Hourly Guardian Daily Report Sweep (Runs at :00 every hour)
cron.schedule('0 * * * *', async () => {
    try {
        const now = new Date();
        const currentHourStr = String(now.getHours()).padStart(2, '0') + ':00';

        console.log(`[Cron Job] Checking guardian report schedules matching hour: ${currentHourStr}`);

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
                const reportMessage = `📊 Mobile Call Shield Daily Summary:\n` +
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

// 2. Automated Safety Check-In Sweep (Runs every hour at :15)
cron.schedule('15 * * * *', async () => {
    try {
        const now = new Date();
        const currentHour = String(now.getHours()).padStart(2, '0');
        console.log(`[Check-In Cron] Starting sweep at ${currentHour}:15`);

        const checkInQuery = `
            SELECT
                pf.id AS portal_feature_id,
                pf.child_id AS dependent_user_id,
                u.user_name,
                u.owner_phone,
                u.pause_mode,
                u.pause_until
            FROM portal_features pf
            JOIN users u ON pf.child_id = u.id
            WHERE pf.feature_name ILIKE '%Safety Check-In%'
              AND pf.is_enabled = true
              AND u.is_active = true
              AND (u.pause_until IS NULL OR u.pause_until <= NOW())
        `;

        const result = await pool.query(checkInQuery);
        console.log(`[Check-In Cron] Matched ${result.rows.length} active check-in configuration(s).`);

        for (const row of result.rows) {
            try {
                console.log(`[Check-In Cron] Evaluated dependent ID ${row.dependent_user_id} (${row.user_name})`);
            } catch (perUserErr) {
                console.error(`[Check-In Cron] Error processing dependent ID ${row.dependent_user_id}:`, perUserErr);
            }
        }
    } catch (err) {
        console.error('[Check-In Cron Error] Failed during scheduled sweep:', err);
    }
});

// 3. Hourly Stride Stats Sync (Runs at :00 every hour)
cron.schedule('0 * * * *', async () => {
    console.log('🔄 [Cron Job] Running sync for stride_stat_data...');
    try {
        await fetchAndStoreStrideStats();
        console.log('✅ [Cron Job] Stride stats sync complete.');
    } catch (err) {
        console.error('❌ [Cron Job Error] Failed to sync Stride stats:', err);
    }
});

// 4. Midnight Twilio Stats Sync (Runs at 12:00 AM every day)
cron.schedule('0 0 * * *', async () => {
    console.log('🔄 [Cron Job] Running midnight sync for Twilio call stats...');
    try {
        await fetchAndStoreTwilioCalls(100);
        console.log('✅ [Cron Job] Midnight Twilio stats sync complete.');
    } catch (err) {
        console.error('❌ [Cron Job Error] Failed to sync Twilio call stats:', err);
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

// ----------------------------------------------------
// Regional Hub Inventory Endpoints
// ----------------------------------------------------
app.get('/api/admin/regional-hubs-stats', authenticateToken, async (req, res) => {
    try {
        const query = `
            SELECT
                h.id AS hub_id,
                h.hub_code,
                h.hub_name,
                STRING_AGG(DISTINCT ac.area_code, ', ') AS area_codes,
                COUNT(n.id) FILTER (WHERE n.user_id IS NULL OR n.status = 'unassigned')::integer AS unassigned_count,
                COUNT(n.id)::integer AS total_count
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

async function provisionHubNumber(req, res) {
    try {
        const { areaCode, hubId } = req.body;

        const availableNumbers = await twilioClient.availablePhoneNumbers('US')
            .local
            .list({ areaCode: areaCode, limit: 1 });

        if (!availableNumbers || availableNumbers.length === 0) {
            return res.status(400).json({ error: "No available phone numbers found for this area code." });
        }

        const targetNumber = availableNumbers[0].phoneNumber;

        const purchasedNumber = await twilioClient.incomingPhoneNumbers.create({
            phoneNumber: targetNumber,
            voiceUrl: 'https://mobilecallshield-backend.onrender.com/api/twilio/voice',
            voiceMethod: 'POST',
            statusCallback: 'https://mobilecallshield-backend.onrender.com/api/twilio/call-status',
            statusCallbackMethod: 'POST'
        });

        await pool.query(
            `INSERT INTO twilio_numbers (phone_number, twilio_sid, hub_id, user_id, status, is_active)
             VALUES ($1, $2, $3, NULL, 'unassigned', true)`,
            [purchasedNumber.phoneNumber, purchasedNumber.sid, hubId]
        );

        return res.status(200).json({
            success: true,
            phoneNumber: purchasedNumber.phoneNumber,
            sid: purchasedNumber.sid,
            message: "Number provisioned and webhooks configured successfully!"
        });
    } catch (error) {
        console.error("Error provisioning Twilio number:", error);
        return res.status(500).json({ error: error.message });
    }
}

app.post('/api/admin/provision-hub-numbers', async (req, res) => {
    let { hubId, count = 1 } = req.body;
    count = parseInt(count, 10) || 1;

    try {
        const acQuery = `SELECT area_code FROM hub_area_codes WHERE hub_id = $1;`;
        const acResult = await pool.query(acQuery, [hubId]);

        if (acResult.rows.length === 0) {
            return res.status(400).json({ success: false, error: 'No area codes configured for this hub.' });
        }

        const targetAreaCode = acResult.rows[0].area_code;
        console.log(`🔍 Searching for ${count} numbers in area code ${targetAreaCode} for hub ID ${hubId}...`);

        const availableNumbers = await twilioClient.availablePhoneNumbers('US')
            .local
            .list({ areaCode: targetAreaCode, limit: count });

        if (availableNumbers.length === 0) {
            return res.status(404).json({ success: false, error: `No Twilio numbers available in area code ${targetAreaCode}.` });
        }

        let addedCount = 0;
        const newlyAdded = [];

        for (const avail of availableNumbers) {
            try {
                const purchasedNumber = await twilioClient.incomingPhoneNumbers.create({
                    phoneNumber: avail.phoneNumber,
                    voiceUrl: 'https://mobilecallshield-backend.onrender.com/api/twilio/voice',
                    voiceMethod: 'POST'
                });

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

// ----------------------------------------------------
// Messaging
// ----------------------------------------------------
app.post('/api/webhook/sms', async (req, res) => {
    try {
        const { from, to, text } = req.body;
        console.log(`📩 Incoming text from ${from} to ${to}: "${text}"`);

        const spamKeywords = ['vote', 'elect', 'campaign', 'sale', 'offer', 'discount', 'deal expires'];
        const isSpam = spamKeywords.some(keyword => text.toLowerCase().includes(keyword));

        if (isSpam) {
            console.log(`🛑 Blocked spam text from ${from}`);
            return res.status(200).json({ status: 'blocked' });
        }

        res.status(200).json({ status: 'received' });
    } catch (err) {
        console.error('Error handling SMS webhook:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ==========================================
// Twilio Call Stats Services & Routes
// ==========================================
app.get('/api/twilio/stats', async (req, res) => {
    const { phone } = req.query;
    if (!phone) {
        return res.status(400).json({ error: 'phone query parameter is required' });
    }

    try {
        await fetchAndStoreTwilioCalls(50);
        const stats = await getWeeklyStatsPerNumber(phone);
        res.json({ phoneNumber: phone, weeklyStats: stats });
    } catch (err) {
        res.status(500).json({ error: 'Failed to retrieve stats' });
    }
});

// ==========================================
// Stride Call Stats Services & Routes
// ==========================================
app.get('/api/stride/stats', async (req, res) => {
    try {
        await fetchAndStoreStrideStats();
        const stats = await getStrideStatsSummary();
        res.json({ success: true, strideStats: stats });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Failed to retrieve stride stats' });
    }
});

// ==========================================
// Guardian - Protected Dashboard & Settings
// ==========================================
app.get('/api/guardians/dependents/:guardianUserId', async (req, res) => {
    const { guardianUserId } = req.params;
    const parsedUserId = parseInt(guardianUserId, 10);

    if (isNaN(parsedUserId)) {
        return res.status(400).json({ success: false, error: 'Invalid user ID format' });
    }

    try {
        const query = `
            SELECT
                u.id,
                u.user_name AS name,
                u.owner_phone AS phone_number,
                COALESCE(u.is_call_shield_enabled, true) AS is_protected
            FROM account_guardians ag
            JOIN users u ON ag.dependent_user_id = u.id
            WHERE ag.guardian_user_id = $1 AND ag.is_active = true
        `;

        const result = await pool.query(query, [parsedUserId]);

        return res.json({
            success: true,
            dependents: result.rows || []
        });
    } catch (error) {
        console.error('Error fetching protected dependents:', error);
        return res.status(500).json({ success: false, error: error.message });
    }
});

async function getGuardianSettings(userId) {
    let res = await pool.query(
        'SELECT * FROM guardian_settings WHERE user_id = $1',
        [userId]
    );

    if (res.rows.length === 0) {
        res = await pool.query(
            `INSERT INTO guardian_settings
                (user_id, threat_feed_enabled, remote_shield_enabled, emergency_actions_enabled, check_ins_enabled)
             VALUES ($1, true, true, true, false)
             RETURNING *`,
            [userId]
        );
    }
    return res.rows[0];
}

// 1. Add / Update Contact & Guardian Links
app.post('/api/guardians/contacts', async (req, res) => {
    const { userId, name, phone, relationship, isGuardian, isPrimary, actorUserId } = req.body;
    const targetUserId = parseInt(userId, 10);
    const effectiveActorId = actorUserId || req.user?.id || targetUserId;

    if (!targetUserId || isNaN(targetUserId) || !name || !phone) {
        return res.status(400).json({ success: false, error: 'User ID, name, and phone are required.' });
    }

    const dbClient = await pool.connect();
    try {
        const actor = await resolveActorRole(dbClient, targetUserId, effectiveActorId);

        // Block co-guardians from adding new co-guardians or primary guardians
        if (isGuardian && actor.role === 'co_guardian') {
            await logAuditEvent(dbClient, {
                dependentUserId: targetUserId,
                performedByUserId: effectiveActorId,
                role: actor.role,
                actionType: 'DENIED_ADD_CO_GUARDIAN',
                changes: { name, phone, reason: 'Only primary guardian or account owner can add guardians' }
            });
            return res.status(403).json({
                success: false,
                error: 'Only the Primary Guardian can assign additional guardians.'
            });
        }

        const normalizedPhone = toE164(phone) || phone;

        // Insert into trusted_contacts
        const contactResult = await dbClient.query(
            `INSERT INTO trusted_contacts (user_id, name, phone_number, relationship)
             VALUES ($1, $2, $3, $4)
             RETURNING id, name, phone_number, relationship`,
            [targetUserId, name, normalizedPhone, relationship || 'Family']
        );
        const newContact = contactResult.rows[0];

        let effectiveIsPrimary = Boolean(isPrimary);

        // Link guardian if flagged and enforce that every guarded protectee has a primary guardian
        if (isGuardian) {
            const guardianUserRes = await dbClient.query(
                `SELECT id FROM users WHERE phone_number = $1 OR owner_phone = $1 LIMIT 1`,
                [normalizedPhone]
            );
            if (guardianUserRes.rowCount > 0) {
                const guardianUserId = guardianUserRes.rows[0].id;

                const existingPrimaryRes = await dbClient.query(
                    `SELECT u.primary_guardian_id,
                            EXISTS (
                                SELECT 1
                                FROM account_guardians ag
                                WHERE ag.dependent_user_id = $1
                                  AND ag.is_active = true
                                  AND ag.permission_level = 'primary'
                            ) AS has_primary_row
                     FROM users u
                     WHERE u.id = $1`,
                    [targetUserId]
                );

                const hasExistingPrimary = Boolean(
                    existingPrimaryRes.rows[0]?.primary_guardian_id ||
                    existingPrimaryRes.rows[0]?.has_primary_row
                );

                effectiveIsPrimary = Boolean(isPrimary) || !hasExistingPrimary;
                const permLevel = effectiveIsPrimary ? 'primary' : 'standard';

                if (effectiveIsPrimary) {
                    await dbClient.query(
                        `UPDATE account_guardians
                         SET permission_level = 'standard'
                         WHERE dependent_user_id = $1
                           AND guardian_user_id != $2
                           AND permission_level = 'primary'`,
                        [targetUserId, guardianUserId]
                    );
                }

                await dbClient.query(
                    `INSERT INTO account_guardians (dependent_user_id, guardian_user_id, permission_level, is_active)
                     VALUES ($1, $2, $3, true)
                     ON CONFLICT (dependent_user_id, guardian_user_id)
                     DO UPDATE SET permission_level = EXCLUDED.permission_level, is_active = true`,
                    [targetUserId, guardianUserId, permLevel]
                );

                if (effectiveIsPrimary) {
                    await dbClient.query(
                        `UPDATE users SET primary_guardian_id = $1 WHERE id = $2`,
                        [guardianUserId, targetUserId]
                    );
                }
            }
        }

        // Audit log contact/guardian creation
        await logAuditEvent(dbClient, {
            dependentUserId: targetUserId,
            performedByUserId: effectiveActorId,
            role: actor.role,
            actionType: isGuardian ? 'ADD_CO_GUARDIAN' : 'ADD_TRUSTED_CONTACT',
            changes: {
                contactId: newContact.id,
                name,
                phone: normalizedPhone,
                isGuardian: Boolean(isGuardian),
                isPrimary: effectiveIsPrimary
            }
        });

        return res.json({
            success: true,
            contact: {
                ...newContact,
                is_primary: effectiveIsPrimary
            }
        });
    } catch (err) {
        console.error('Error creating contact/guardian:', err);
        return res.status(500).json({ success: false, error: 'Server error saving contact.' });
    } finally {
        dbClient.release();
    }
});

// Get Contact & Guardian Links
app.get('/api/guardians/settings/:userId', async (req, res) => {
    try {
        const userId = parseInt(req.params.userId, 10);
        const settings = await getGuardianSettings(userId);

        res.json({
            success: true,
            settings: {
                userId: settings.user_id,
                threatFeedEnabled: settings.threat_feed_enabled,
                remoteShieldEnabled: settings.remote_shield_enabled,
                emergencyActionsEnabled: settings.emergency_actions_enabled,
                checkInsEnabled: settings.check_ins_enabled
            }
        });
    } catch (error) {
        console.error('Error fetching guardian settings:', error);
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

app.put('/api/guardians/settings/:userId', async (req, res) => {
    try {
        const userId = parseInt(req.params.userId, 10);
        const { threatFeedEnabled, remoteShieldEnabled, emergencyActionsEnabled, checkInsEnabled } = req.body;

        const query = `
            INSERT INTO guardian_settings
                (user_id, threat_feed_enabled, remote_shield_enabled, emergency_actions_enabled, check_ins_enabled, updated_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            ON CONFLICT (user_id) DO UPDATE SET
                threat_feed_enabled = EXCLUDED.threat_feed_enabled,
                remote_shield_enabled = EXCLUDED.remote_shield_enabled,
                emergency_actions_enabled = EXCLUDED.emergency_actions_enabled,
                check_ins_enabled = EXCLUDED.check_ins_enabled,
                updated_at = NOW()
            RETURNING *;
        `;

        const values = [
            userId,
            threatFeedEnabled ?? true,
            remoteShieldEnabled ?? true,
            emergencyActionsEnabled ?? true,
            checkInsEnabled ?? false
        ];

        const result = await pool.query(query, values);
        const updated = result.rows[0];

        res.json({
            success: true,
            message: 'Guardian settings updated successfully',
            settings: {
                userId: updated.user_id,
                threatFeedEnabled: updated.threat_feed_enabled,
                remoteShieldEnabled: updated.remote_shield_enabled,
                emergencyActionsEnabled: updated.emergency_actions_enabled,
                checkInsEnabled: updated.check_ins_enabled
            }
        });
    } catch (error) {
        console.error('Error updating guardian settings:', error);
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

app.get('/api/guardians/call-logs/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const query = `
            SELECT id, caller_number, caller_name, call_type, risk_level, timestamp, audio_url, is_blocked
            FROM call_logs
            WHERE user_id = $1
            ORDER BY timestamp DESC
            LIMIT 50;
        `;
        const result = await pool.query(query, [userId]);
        res.json({ success: true, logs: result.rows });
    } catch (err) {
        console.error('Error fetching call logs:', err);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

app.post('/api/guardians/call-logs', async (req, res) => {
    try {
        const { userId, callerNumber, callerName, callType, riskLevel, audioUrl, isBlocked } = req.body;
        const query = `
            INSERT INTO call_logs (user_id, caller_number, caller_name, call_type, risk_level, timestamp, audio_url, is_blocked)
            VALUES ($1, $2, $3, $4, $5, NOW(), $6, $7)
            RETURNING id, caller_number, risk_level, timestamp;
        `;
        const result = await pool.query(query, [userId, callerNumber, callerName, callType, riskLevel, audioUrl, isBlocked]);
        res.json({ success: true, log: result.rows[0] });
    } catch (err) {
        console.error('Error saving call log:', err);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

app.put('/api/guardians/report-settings', async (req, res) => {
    let { ownerId, guardianId, guardianPhone, guardianEmail, sendViaSms, sendViaEmail, reportTime } = req.body;

    try {
        const userCheck = await pool.query('SELECT id FROM users WHERE id = $1', [guardianId]);
        if (userCheck.rows.length === 0) {
            const phoneMatch = await pool.query('SELECT id FROM users WHERE owner_phone = $1', [guardianPhone]);
            if (phoneMatch.rows.length > 0) {
                guardianId = phoneMatch.rows[0].id;
            } else {
                return res.status(400).json({ success: false, error: "Guardian ID does not exist in users table." });
            }
        }

        const query = `
            INSERT INTO guardian_report_settings
                (owner_id, guardian_id, guardian_phone, guardian_email, send_via_sms, send_via_email, report_time)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (guardian_id)
            DO UPDATE SET
                guardian_phone = EXCLUDED.guardian_phone,
                guardian_email = EXCLUDED.guardian_email,
                send_via_sms = EXCLUDED.send_via_sms,
                send_via_email = EXCLUDED.send_via_email,
                report_time = EXCLUDED.report_time
            RETURNING *;
        `;

        const values = [ownerId, guardianId, guardianPhone, guardianEmail, sendViaSms ?? true, sendViaEmail ?? false, reportTime];
        const result = await pool.query(query, values);

        res.json({ success: true, settings: result.rows[0] });
    } catch (err) {
        console.error("❌ Error updating guardian report settings:", err);
        res.status(500).json({ success: false, error: "Failed to update report settings." });
    }
});

// ==========================================
// Dynamic Tables for app sections (Display and reporting)
// ==========================================
app.get('/api/system/menu-tree', async (req, res) => {
    try {
        const query = `
            SELECT
                sf.feature_id as system_id,
                sf.function_type,
                pf.id as portal_id,
                pf.child_id,
                pf.feature_name,
                pf.description,
                pf.xcode_table,
                pf.android_studio_table,
                pf.is_enabled,
                pf.sort_order,
                pf.sub_sort_order
            FROM system_features sf
            LEFT JOIN portal_features pf ON sf.feature_id = pf.feature_id
            WHERE sf.is_active = true AND pf.is_enabled = true
            ORDER BY sf.feature_id, pf.sort_order, pf.sub_sort_order;
        `;

        const result = await pool.query(query);
        res.json({ success: true, menuTree: result.rows });
    } catch (err) {
        console.error('Error fetching menu tree:', err);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

app.get('/api/guardians/features/:id', async (req, res) => {
    try {
        const query = `
            SELECT
                pf.id,
                pf.feature_name,
                pf.description,
                pf.is_enabled,
                pf.sort_order,
                pf.sub_sort_order
            FROM portal_features pf
            JOIN system_features sf ON pf.child_id = sf.feature_id
            WHERE sf.is_active = true
              AND pf.is_enabled = true
              AND sf.function_type = 'Guardian Portal'
            ORDER BY pf.sort_order ASC, pf.sub_sort_order ASC;
        `;
        const result = await pool.query(query);
        res.json({ success: true, guardianFeatures: result.rows });
    } catch (err) {
        console.error('Error fetching guardian portal features:', err);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

app.put('/api/guardians/features/:id', async (req, res) => {
    try {
        const { featureId, isEnabled } = req.body;

        if (!featureId || isEnabled === undefined) {
            return res.status(400).json({ success: false, error: 'featureId and isEnabled are required' });
        }

        const query = `
            UPDATE portal_features
            SET is_enabled = $1
            WHERE id = $2
            RETURNING id, feature_name, is_enabled;
        `;

        const result = await pool.query(query, [isEnabled, featureId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, error: 'Feature not found' });
        }

        res.json({
            success: true,
            message: 'Protectee feature state updated successfully',
            feature: result.rows[0]
        });
    } catch (err) {
        console.error('Error updating protectee feature state:', err);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

app.get('/api/dashboard/features/:id', async (req, res) => {
    try {
        const query = `
            SELECT
                pf.id,
                pf.feature_name,
                pf.description,
                pf.is_enabled,
                pf.sort_order,
                pf.sub_sort_order
            FROM portal_features pf
            JOIN system_features sf ON pf.feature_id = sf.feature_id
            WHERE sf.is_active = true
              AND pf.is_enabled = true
              AND sf.function_type = 'MainDashboard'
              AND pf.child_id IS NULL
            ORDER BY pf.sort_order ASC, pf.sub_sort_order ASC;
        `;
        const result = await pool.query(query);
        res.json({ success: true, guardianFeatures: result.rows });
    } catch (err) {
        console.error('Error fetching guardian portal features:', err);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// ==========================================
// TEMPORARY QUIET / VACATION PAUSE ENDPOINTS
// ==========================================
function getNext8AmCentralDate(now = new Date()) {
    const formatter = new Intl.DateTimeFormat('en-US', {
        timeZone: 'America/Chicago',
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        hour12: false
    });

    const parts = formatter.formatToParts(now).reduce((acc, p) => {
        if (p.type !== 'literal') acc[p.type] = p.value;
        return acc;
    }, {});

    let year = parseInt(parts.year, 10);
    let month = parseInt(parts.month, 10);
    let day = parseInt(parts.day, 10);
    const currentHour = parseInt(parts.hour, 10);

    if (currentHour >= 8) {
        const advance = new Date(Date.UTC(year, month - 1, day + 1));
        year = advance.getUTCFullYear();
        month = advance.getUTCMonth() + 1;
        day = advance.getUTCDate();
    }

    const probeUtc = new Date(Date.UTC(year, month - 1, day, 14, 0, 0));
    const tzName = new Intl.DateTimeFormat('en-US', {
        timeZone: 'America/Chicago',
        timeZoneName: 'short'
    }).formatToParts(probeUtc).find(p => p.type === 'timeZoneName')?.value;

    const offset = tzName === 'CDT' ? '-05:00' : '-06:00';
    const mm = String(month).padStart(2, '0');
    const dd = String(day).padStart(2, '0');

    return new Date(`${year}-${mm}-${dd}T08:00:00${offset}`);
}

app.get('/api/user/pause-status/:userId', async (req, res) => {
    const parsedUserId = parseInt(req.params.userId, 10);

    if (isNaN(parsedUserId)) {
        return res.status(400).json({ success: false, error: 'Invalid userId' });
    }

    try {
        const result = await pool.query(
            `SELECT pause_mode, pause_until FROM users WHERE id = $1`,
            [parsedUserId]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }

        const row = result.rows[0];
        const now = new Date();
        const isPaused = row.pause_until && new Date(row.pause_until) > now;

        return res.json({
            success: true,
            isPaused: Boolean(isPaused),
            pauseMode: isPaused ? row.pause_mode : null,
            pauseUntil: isPaused ? row.pause_until : null
        });
    } catch (error) {
        console.error('Error getting pause status:', error);
        return res.status(500).json({ success: false, error: error.message });
    }
});

// ==========================================
// Server Start
// ==========================================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Mobile Call Shield server running on port ${PORT}`);
});