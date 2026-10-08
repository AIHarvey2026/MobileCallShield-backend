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
        // Find which user owns this shield number
        const userResult = await pool.query(
            `SELECT u.id as user_id, u.owner_phone FROM phone_numbers p JOIN users u ON p.user_id = u.id WHERE p.shield_number = $1`,
            [shieldNumber]
        );

        // Fallback for single-tenant / local testing if phone_numbers table isn't seeded yet
        let userId = null;
        let ownerPhone = process.env.PERSONAL_PHONE_NUMBER;

        if (userResult.rows.length > 0) {
            userId = userResult.rows[0].user_id;
            ownerPhone = userResult.rows[0].owner_phone || process.env.PERSONAL_PHONE_NUMBER;
        }

        let isTrusted = false;

        if (userId) {
            // Check if caller is in this user's trusted contacts list
            const contactResult = await pool.query(
                `SELECT is_guardian FROM trusted_contacts WHERE user_id = $1 AND phone_number = $2`,
                [userId, callerNumber]
            );
            if (contactResult.rows.length > 0) {
                isTrusted = true;
                console.log(`[TRUSTED] Caller found in database for user ${userId}. Bypassing PIN.`);
            }
        }

        if (isTrusted) {
            twiml.say({ voice: 'alice' }, "Connecting your call.");
            twiml.dial(ownerPhone);
        } else {
            console.log("[UNKNOWN CALLER] Prompting for 4-digit PIN.");
            const gather = twiml.gather({
                numDigits: 4,
                action: `/verify-pin?ownerPhone=${encodeURIComponent(ownerPhone)}`,
                method: 'POST',
                timeout: 10
            });
            gather.say(
                { voice: 'alice' },
                "Please enter your four-digit security PIN on your phone keypad to reach this household."
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

// 2. PIN VERIFICATION ENDPOINT
app.post('/verify-pin', (req, res) => {
    const twiml = new twilio.twiml.VoiceResponse(); // Fixed from twirl
    const enteredPin = req.body.Digits;
    const ownerPhone = req.query.ownerPhone || process.env.PERSONAL_PHONE_NUMBER;

    console.log(`[PIN VERIFY] Entered digits: ${enteredPin}`);

    if (enteredPin === DEFAULT_MASTER_PIN) {
        twiml.say({ voice: 'alice' }, "PIN accepted. Connecting your call now.");
        twiml.dial(ownerPhone);
    } else {
        twiml.say({ voice: 'alice' }, "Incorrect PIN. Goodbye.");
        twiml.hangup();
    }

    res.type('text/xml');
    res.send(twiml.toString());
});

// Check if user exist or new user will be register
app.post('/api/register', async (req, res) => {
    try {
        const { email, password } = req.body;
       
        // Step 1: Check if the email already exists
        const existingUser = await pool.query('SELECT id FROM public.users WHERE email = $1', [email]);
       
        if (existingUser.rows.length > 0) {
            // Email IS found -> Reject registration
            return res.status(400).json({ success: false, error: "Email is already in use." });
        }
       
        // Step 2: No email found -> Run the INSERT statement
        const insertQuery = `
            INSERT INTO public.users (email, password, role, status)
            VALUES ($1, $2, 'user', 'trialing')
            RETURNING id, email, created_at;
        `;
       
        const result = await pool.query(insertQuery, [email, password]);
        const newUser = result.rows[0];

        // Step 3: Return the new integer ID back to the app
        res.status(201).json({
            success: true,
            userId: newUser.id, // e.g., 2, 3, etc.
            email: newUser.email,
            message: "User registered successfully!"
        });
       
    } catch (err) {
        console.error("[REGISTER ERROR]", err.message);
        res.status(500).json({ success: false, error: err.message });
    }
});

// 4. USER LOGIN ENDPOINT
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Check if user exists with matching email and password
        const result = await pool.query(
            'SELECT id, email FROM public.users WHERE email = $1 AND password = $2',
            [email, password]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ success: false, error: "Invalid email or password." });
        }

        const user = result.rows[0];



        // Return user object containing the integer ID expected by the Android app
        res.status(200).json({
            success: true,
            user: {
                id: user.id,   // Integer ID from PostgreSQL SERIAL schema
                email: user.email
            },
            message: "Login successful!"
        });

    } catch (err) {
        console.error("[LOGIN ERROR]", err.message);
        res.status(500).json({ success: false, error: err.message });
    }
});

// 3. API ENDPOINT FOR ANDROID APP TO SYNC CONTACTS (WITH UPSERT)
app.post('/api/contacts', async (req, res) => {
    try {
        console.log("[API CONTACT BODY RECEIVED]", req.body);

        let userId = req.body.userId || req.body.user_id;
        const name = req.body.name;
        const phoneNumber = req.body.phoneNumber || req.body.phone_number;
        const isGuardian = req.body.isGuardian !== undefined ? req.body.isGuardian : req.body.is_guardian;

        // Parse and validate incoming userId as an integer, fallback to test user ID 1
        userId = parseInt(userId, 10);
        if (isNaN(userId) || userId <= 0) {
            userId = 1; // Default fallback to our test user
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`[SERVER] Senior Scam Shield backend running on port ${PORT}`);
});