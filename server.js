require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const twilio = require('twilio');
const { Pool } = require('pg');

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.json());

// PostgreSQL Connection Pool
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Fallback Master PIN if not user-specific
const DEFAULT_MASTER_PIN = process.env.MASTER_PIN || "1234";

// 1. INCOMING CALL WEBHOOK (Hit by Twilio when a call rings your shield number)
app.post('/voice', async (req, res) => {
    const twiml = new twilio.twiml.VoiceResponse();
    const callerNumber = req.body.From; // Who is calling
    const shieldNumber = req.body.To;   // Your Twilio Shield phone number

    console.log(`[INCOMING CALL] From: ${callerNumber} to Shield: ${shieldNumber}`);

    try {
        const userResult = await pool.query(
            `SELECT u.id as user_id, u.owner_phone, u.passcode FROM phone_numbers p JOIN users u ON p.user_id = u.id WHERE p.phone_number = $1`,
            [shieldNumber]
        );

        let userId = null;
        let ownerPhone = process.env.PERSONAL_PHONE_NUMBER;
        let userPasscode = DEFAULT_MASTER_PIN;

        if (userResult.rows.length > 0) {
            userId = userResult.rows[0].user_id;
            ownerPhone = userResult.rows[0].owner_phone || process.env.PERSONAL_PHONE_NUMBER;
            userPasscode = userResult.rows[0].passcode || DEFAULT_MASTER_PIN;
        }

        let isTrusted = false;

        if (userId) {
            const contactResult = await pool.query(
                `SELECT is_guardian FROM trusted_contacts WHERE user_id = $1 AND phone_number = $2`,
                [userId, callerNumber]
            );
            if (contactResult.rows.length > 0) {
                isTrusted = true;
                console.log(`[TRUSTED] Caller found in database for user ${userId}. Bypassing passcode.`);
            }
        }

        if (isTrusted) {
            twiml.say({ voice: 'alice' }, "Connecting your call.");
            twiml.dial(ownerPhone);
        } else {
            console.log("[UNKNOWN CALLER] Prompting for security passcode.");
            const gather = twiml.gather({
                numDigits: 4,
                action: `/verify-pin?ownerPhone=${encodeURIComponent(ownerPhone)}&expectedPasscode=${encodeURIComponent(userPasscode)}`,
                method: 'POST',
                timeout: 10
            });
            gather.say(
                { voice: 'alice' },
                "Please enter your four-digit security passcode on your phone keypad to reach this household."
            );

            twiml.say({ voice: 'alice' }, "No input received. Goodbye.");
            twiml.hangup();
        }
    } catch (err) {
        console.error("[VOICE WEBHOOK ERROR]", err);
        twiml.say({ voice: 'alice' }, "An error occurred processing your call. Goodbye.");
        twiml.hangup();
    }

    res.type('text/xml');
    res.send(twiml.toString());
});

// 2. PIN / PASSCODE VERIFICATION ENDPOINT
app.post('/verify-pin', (req, res) => {
    const twiml = new twilio.twiml.VoiceResponse();
    const enteredPin = req.body.Digits;
    const ownerPhone = req.query.ownerPhone || process.env.PERSONAL_PHONE_NUMBER;
    const expectedPasscode = req.query.expectedPasscode || DEFAULT_MASTER_PIN;

    console.log(`[PIN VERIFY] Entered digits: ${enteredPin}`);

    if (enteredPin === expectedPasscode) {
        twiml.say({ voice: 'alice' }, "Passcode accepted. Connecting your call now.");
        twiml.dial(ownerPhone);
    } else {
        twiml.say({ voice: 'alice' }, "Incorrect passcode. Goodbye.");
        twiml.hangup();
    }

    res.type('text/xml');
    res.send(twiml.toString());
});

// 3. REGISTER ENDPOINT
app.post('/api/register', async (req, res) => {
    try {
        const { email, password, address, city, state, zip, country, privacyAgreed } = req.body;
        
        // Strict server-side validation check
        if (!privacyAgreed) {
            return res.status(400).json({ success: false, error: "You must agree to the privacy policy to register." });
        }
        
        const existingUser = await pool.query('SELECT id FROM public.users WHERE email = $1', [email]);
        if (existingUser.rows.length > 0) {
            return res.status(400).json({ success: false, error: "Email is already in use." });
        }
        
        const insertQuery = `
            INSERT INTO public.users (email, password, role, status, address, city, state, zip, country, privacy_agreed)
            VALUES ($1, $2, 'user', 'trialing', $3, $4, $5, $6, $7, $8)
            RETURNING id, email, created_at;
        `;
        
        const result = await pool.query(insertQuery, [
            email, password, 
            address || null, 
            city || null, 
            state || null, 
            zip || null, 
            country || 'United States',
            privacyAgreed
        ]);
        
        const newUser = result.rows[0];

        res.status(201).json({
            success: true,
            userId: newUser.id,
            email: newUser.email,
            message: "User registered successfully!"
        });
        
    } catch (err) {
        console.error("[REGISTER ERROR DETAIL]:", err.message);
        res.status(500).json({ success: false, error: "DB Error: " + err.message });
    }
});

// 4. USER LOGIN ENDPOINT
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const result = await pool.query(
            'SELECT id, email FROM public.users WHERE email = $1 AND password = $2',
            [email, password]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ success: false, error: "Invalid email or password." });
        }

        const user = result.rows[0];

        res.status(200).json({
            success: true,
            user: {
                id: user.id,
                email: user.email
            },
            message: "Login successful!"
        });

    } catch (err) {
        console.error("[LOGIN ERROR]", err.message);
        res.status(500).json({ success: false, error: err.message });
    }
});

// 5. API ENDPOINT FOR CONTACTS SYNC (WITH UPSERT)
app.post('/api/contacts', async (req, res) => {
    try {
        let userId = req.body.userId || req.body.user_id;
        const name = req.body.name;
        const phoneNumber = req.body.phoneNumber || req.body.phone_number;
        const isGuardian = req.body.isGuardian !== undefined ? req.body.isGuardian : req.body.is_guardian;

        userId = parseInt(userId, 10);
        if (isNaN(userId) || userId <= 0) {
            userId = 1;
        }

        const query = `
            INSERT INTO public.trusted_contacts (user_id, name, phone_number, is_guardian)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (user_id, phone_number)
            DO UPDATE SET name = EXCLUDED.name, is_guardian = EXCLUDED.is_guardian
            RETURNING *
        `;
        const values = [userId, name, phoneNumber, isGuardian ?? false];
        
        const result = await pool.query(query, values);
        res.status(200).json({ success: true, contact: result.rows[0] });
    } catch (err) {
        console.error("[API CONTACT ERROR DETAIL]", err.message);
        res.status(500).json({ success: false, error: err.message });
    }
});

// 6. PHONE NUMBER ASSIGNMENT SIGN-IN/SYNC ENDPOINT
app.post('/api/auth/signin', async (req, res) => {
    const { deviceId, userPhoneNumber } = req.body;

    try {
        let queryResult = await pool.query(
            'SELECT * FROM phone_numbers WHERE user_id = $1 AND is_active = true LIMIT 1',
            [deviceId]
        );

        let assignedNumber = queryResult.rows[0];

        if (!assignedNumber) {
            const assignmentResult = await pool.query(`
                UPDATE phone_numbers 
                SET user_id = $1, is_active = true 
                WHERE id = (
                    SELECT id FROM phone_numbers 
                    WHERE user_id IS NULL 
                    LIMIT 1 
                    FOR UPDATE
                )
                RETURNING *;
            `, [deviceId]);

            if (assignmentResult.rows.length === 0) {
                return res.status(400).json({ error: "No available phone numbers in the pool. Please add more." });
            }

            assignedNumber = assignmentResult.rows[0];
        }

        res.status(200).json({
            success: true,
            assignedPhoneNumber: assignedNumber.phone_number,
            label: assignedNumber.label
        });

    } catch (err) {
        console.error("Error during phone number assignment:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});

// 7. GET CONTACTS ENDPOINT
app.get('/api/contacts', async (req, res) => {
    try {
        let userId = req.query.userId;
        userId = parseInt(userId, 10);
        if (isNaN(userId) || userId <= 0) {
            userId = 1;
        }

        const result = await pool.query(
            'SELECT id, user_id AS "userId", name, phone_number AS "phoneNumber", is_guardian AS "isGuardian" FROM public.trusted_contacts WHERE user_id = $1 ORDER BY id DESC',
            [userId]
        );

        res.status(200).json({ success: true, contacts: result.rows });
    } catch (err) {
        console.error("[GET CONTACTS ERROR]", err.message);
        res.status(500).json({ success: false, error: err.message });
    }
});

// 8. UPDATE USER PIN / PASSCODE ENDPOINT
app.post('/api/users/pin', async (req, res) => {
    try {
        let userId = req.body.userId || req.body.user_id;
        const newPin = req.body.pin || req.body.passcode;

        userId = parseInt(userId, 10);
        if (isNaN(userId) || userId <= 0) {
            userId = 1;
        }

        if (!newPin || newPin.length !== 4 || isNaN(newPin)) {
            return res.status(400).json({ success: false, error: "Passcode must be a 4-digit number." });
        }

        await pool.query(
            'UPDATE public.users SET passcode = $1 WHERE id = $2',
            [newPin, userId]
        );

        console.log(`[PASSCODE UPDATE] User ${userId} updated their security passcode.`);
        res.status(200).json({ success: true, message: "Passcode updated successfully!" });
    } catch (err) {
        console.error("[PASSCODE UPDATE ERROR]", err.message);
        res.status(500).json({ success: false, error: err.message });
    }
});

// 9. CALL LOGS ENDPOINT
app.get('/api/call-logs/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const result = await pool.query(
            'SELECT * FROM call_logs WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50',
            [userId]
        );
        res.json({ success: true, logs: result.rows });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 10. UPDATE USER PHONE NUMBER ENDPOINT
app.post('/api/users/phone-number', async (req, res) => {
    try {
        let userId = req.body.userId || req.body.user_id;
        const newPhoneNumber = req.body.newPhoneNumber || req.body.new_phone_number;

        userId = parseInt(userId, 10);
        if (isNaN(userId) || userId <= 0) {
            return res.status(400).json({ success: false, error: "Invalid user ID." });
        }

        if (!newPhoneNumber) {
            return res.status(400).json({ success: false, error: "New phone number is required." });
        }

        await pool.query(
            'UPDATE public.users SET owner_phone = $1 WHERE id = $2',
            [newPhoneNumber, userId]
        );

        console.log(`[PHONE UPDATE] User ${userId} updated their personal phone number to ${newPhoneNumber}.`);
        res.status(200).json({ success: true, message: "Phone number updated successfully!" });

    } catch (err) {
        console.error("[PHONE UPDATE ERROR]", err.message);
        res.status(500).json({ success: false, error: err.message });
    }
});

// 11. GET APP SETTINGS ENDPOINT
app.get('/api/settings', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM public.app_settings LIMIT 1');
        
        res.status(200).json({ 
            success: true, 
            settings: result.rows[0] || {} 
        });
    } catch (err) {
        console.error("[SETTINGS ERROR]", err.message);
        res.status(500).json({ success: false, error: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`[SERVER] Senior Scam Shield backend running on port ${PORT}`);
});