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
        const userQuery = `
            u.id as user_id, u.owner_phone, u.email
            FROM phone_numbers p
            JOIN users u ON p.user_id = u.id
            WHERE p.shield_number = $1
        `;
        // Let's run a clean query
        const userResult = await pool.query(
            `SELECT u.id as user_id, u.owner_phone FROM phone_numbers p JOIN users u ON p.user_id = u.id WHERE p.shield_number = $1`,
            [shieldNumber]
        );

        // Fallback for single-tenant / local testing if phone_numbers table isn't seeded yet
        let userId = null;
        let ownerPhone = process.env.PERSONAL_PHONE_NUMBER;

        if (userResult.rows.length > 0) {
            userId = userResult.rows.length > 0 ? userResult.rows[0].user_id : null;
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
    const twiml = new twilio.twiml.VoiceResponse();
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

// 3. API ENDPOINT FOR ANDROID APP TO SYNC CONTACTS
app.post('/api/contacts', async (req, res) => {
    const { userId, name, phoneNumber, isGuardian } = req.body;
    
    try {
        const query = `
            INSERT INTO trusted_contacts (user_id, phone_number, name, is_guardian)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (user_id, phone_number) 
            DO UPDATE SET name = EXCLUDED.name, is_guardian = EXCLUDED.is_guardian
            RETURNING *;
        `;
        const values = [userId || null, phoneNumber, name, isGuardian || false];
        const result = await pool.query(query, values);
        
        res.status(201).json({ success: true, contact: result.rows[0] });
    } catch (err) {
        console.error("[API CONTACT ERROR]", err);
        res.status(500).json({ success: false, error: "Database error saving contact" });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`[SERVER] Senior Scam Shield backend running on port ${PORT}`);
});