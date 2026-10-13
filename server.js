const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const twilio = require('twilio');

const app = express();
const PORT = process.env.PORT || 3000;

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
            callback(null, true); // Set to true during initial beta testing
        }
    },
    credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Health Check Endpoint for UptimeRobot / Monitoring
app.get('/health', (req, res) => {
    res.status(200).send('Mobile Call Shield Backend is active and healthy.');
});

// ----------------------------------------------------
// App Settings Endpoint (Logo and Title Sync)
// ----------------------------------------------------
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

// ----------------------------------------------------
// 3. User Authentication Routes
// ----------------------------------------------------

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
    const { name, phoneNumber, email, password } = req.body;

    if (!phoneNumber || !password || !email) {
        return res.status(400).json({ error: 'Phone number, email, and password are required.' });
    }

    try {
        const existingUser = await pool.query(
            'SELECT * FROM users WHERE owner_phone = $1 OR email = $2 OR user_name = $2', 
            [phoneNumber, email]
        );
        
        if (existingUser.rows.length > 0) {
            return res.status(409).json({ error: 'An account with this phone number or email already exists.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await pool.query(
            'INSERT INTO users (user_name, owner_phone, email, password, created_at) VALUES ($1, $2, $3, $4, NOW()) RETURNING id, user_name, owner_phone, email',
            [email, phoneNumber, email, hashedPassword]
        );

        res.status(201).json({
            success: true,
            message: 'User registered successfully!',
            user: {
                id: newUser.rows[0].id,
                name: newUser.rows[0].user_name,
                phoneNumber: newUser.rows[0].owner_phone,
                email: newUser.rows[0].email
            }
        });
    } catch (err) {
        console.error('Error during registration:', err);
        res.status(500).json({ error: 'Server error creating user account.' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;

    console.log(`[Login Attempt] Username/Email received: "${username}" | Password received: "${password}"`);

    try {
        const result = await pool.query(
            'SELECT * FROM users WHERE user_name = $1 OR email = $1', 
            [username]
        );

        if (result.rows.length === 0) {
            console.log(`[Login Error] User not found in database for: "${username}"`);
            return res.status(401).json({ error: 'Invalid credentials: User not found.' });
        }

        const user = result.rows[0];
        console.log(`[Login Debug] User found! DB Password is: "${user.password}"`);

        const match = (password === user.password) || await bcrypt.compare(password, user.password).catch(() => false);

        if (!match) {
            console.log(`[Login Error] Password mismatch! Sent: "${password}" vs DB: "${user.password}"`);
            return res.status(401).json({ error: 'Invalid credentials: Password incorrect.' });
        }

        console.log(`[Login Success] User ID ${user.id} logged in successfully.`);
        res.status(200).json({
            success: true,
            message: 'Login successful!',
            user: {
                id: user.id,
                name: user.user_name,
                phoneNumber: user.owner_phone,
                email: user.email
            }
        });
    } catch (err) {
        console.error('Error during login:', err);
        res.status(500).json({ error: 'Server error logging in.' });
    }
});

// ----------------------------------------------------
// 4. Beta Tester Portal Error Logging Endpoint
// ----------------------------------------------------
app.post('/api/tester-feedback', async (req, res) => {
    const { testerName, device, errorDetails } = req.body;

    try {
        console.log(`\n--- [BETA TESTER FEEDBACK] ---`);
        console.log(`Tester: ${testerName} | Device: ${device}`);
        console.log(`Details: ${errorDetails}\n`);

        await pool.query(
            'INSERT INTO tester_feedback (tester_name, device, details, created_at) VALUES ($1, $2, $3, NOW())',
            [testerName, device, errorDetails]
        ).catch(err => console.log('Notice: tester_feedback table optional:', err.message));

        res.send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Feedback Received</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="bg-slate-50 flex items-center justify-center h-screen font-sans">
                <div class="bg-white p-8 rounded-2xl shadow-lg text-center max-w-md border border-slate-200">
                    <div class="text-emerald-500 text-5xl mb-4">✓</div>
                    <h2 class="text-2xl font-bold text-slate-800 mb-2">Thank You, ${testerName}!</h2>
                    <p class="text-slate-600 mb-6">Your report for <strong>${device}</strong> has been logged successfully.</p>
                    <a href="/" class="bg-emerald-500 text-white font-bold px-6 py-3 rounded-lg hover:bg-emerald-600 transition-all inline-block">Return to Homepage</a>
                </div>
            </body>
            </html>
        `);
    } catch (err) {
        console.error('Error logging feedback:', err);
        res.status(500).send('Error logging feedback report.');
    }
});

// ----------------------------------------------------
// 5. Twilio Voice Webhooks (Incoming Call Screening)
// ----------------------------------------------------
app.post('/voice', async (req, res) => {
    const twilioNumber = req.body.To;
    console.log(`[Twilio Call] Incoming call to Twilio number: ${twilioNumber}`);

    const twiml = new twilio.twiml.VoiceResponse();

    try {
        const userResult = await pool.query(`
            SELECT u.owner_phone, u.is_call_shield_enabled 
            FROM phone_numbers pn
            JOIN users u ON pn.user_id = u.id
            WHERE pn.phone_number = $1 AND pn.is_active = true
        `, [twilioNumber]);

        if (userResult.rows.length > 0) {
            const user = userResult.rows[0];
            
            if (user.is_call_shield_enabled === false) {
                console.log(`[Call Shield Disabled] Direct dialing owner phone: ${user.owner_phone}`);
                twiml.dial(user.owner_phone);
                res.type('text/xml');
                return res.send(twiml.toString());
            }
        }
    } catch (err) {
        console.error('Error checking shield status on incoming call:', err);
    }

    const gather = twiml.gather({
        input: 'speech',
        action: '/process-passphrase',
        method: 'POST',
        timeout: 5,
        speechTimeout: 'auto'
    });

    gather.say({ 
        voice: 'Polly.Matthew-Neural' 
    }, 'Hello! This number is protected by Mobile Call Shield. Please state your name or passcode after the tone.');

    twiml.say({ 
        voice: 'Polly.Matthew-Neural' 
    }, 'We did not receive any response. Goodbye.');
    
    twiml.hangup();

    res.type('text/xml');
    res.send(twiml.toString());
});

app.post('/process-passphrase', async (req, res) => {
    const twiml = new twilio.twiml.VoiceResponse();
    const spokenPassphrase = (req.body.SpeechResult || '').toLowerCase().trim();
    const twilioNumber = req.body.To;

    console.log(`[Twilio Call] Incoming call to ${twilioNumber} | Caller said: "${spokenPassphrase}"`);

    try {
        const userResult = await pool.query(`
            SELECT u.passcode, u.owner_phone, u.id 
            FROM phone_numbers pn
            JOIN users u ON pn.user_id = u.id
            WHERE pn.phone_number = $1 AND pn.is_active = true
        `, [twilioNumber]);
        
        if (userResult.rows.length === 0) {
            twiml.say({ voice: 'Polly.Matthew-Neural' }, 'No active account found for this phone number.');
            twiml.hangup();
            res.type('text/xml');
            return res.send(twiml.toString());
        }

        const user = userResult.rows[0];
        const forwardNumber = user.owner_phone;
        const userPasscode = (user.passcode || '1234').toLowerCase().trim();

        if (spokenPassphrase.length > 0 && spokenPassphrase.includes(userPasscode)) {
            twiml.say({ voice: 'Polly.Matthew-Neural' }, 'Passcode accepted. Connecting your call now.');
            twiml.dial(forwardNumber);
        } else {
            twiml.say({ 
                voice: 'Polly.Matthew-Neural' 
            }, 'Passcode not recognized. If you are a doctor, pharmacy, or family member, please leave a message after the tone with your name and callback number. Press pound when finished.');
            
            twiml.record({
                action: '/save-voicemail',
                method: 'POST',
                maxLength: 60,
                finishOnKey: '#'
            });
        }
    } catch (err) {
        console.error('Database lookup error during passcode verification:', err);
        twiml.say({ voice: 'Polly.Matthew-Neural' }, 'An internal error occurred processing your call.');
        twiml.hangup();
    }

    res.type('text/xml');
    res.send(twiml.toString());
});

app.post('/save-voicemail', (req, res) => {
    const recordingUrl = req.body.RecordingUrl;
    const callerNumber = req.body.From;
    const calledNumber = req.body.To;

    console.log(`[Voicemail Received] From: ${callerNumber} | To: ${calledNumber}`);
    console.log(`Recording Audio URL: ${recordingUrl}.mp3`);

    const twiml = new twilio.twiml.VoiceResponse();
    twiml.say({ voice: 'Polly.Matthew-Neural' }, 'Thank you. Your message has been saved. Goodbye.');
    twiml.hangup();

    res.type('text/xml');
    res.send(twiml.toString());
});

// ----------------------------------------------------
// 6. Trusted Contacts & Guardian Routes
// ----------------------------------------------------

// Fetch all trusted contacts for a user
app.get('/api/trusted-contacts/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const result = await pool.query(
            'SELECT id, user_id, name, phone_number, is_guardian FROM trusted_contacts WHERE user_id = $1', 
            [userId]
        );
        res.json(result.rows);
    } catch (err) {
        console.error('Error fetching trusted contacts:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Toggle guardian status directly by contact ID
app.patch('/api/trusted-contacts/:id/guardian', async (req, res) => {
    const contactId = req.params.id;
    const { is_guardian } = req.body;
    
    try {
        const result = await pool.query(
            'UPDATE trusted_contacts SET is_guardian = $1 WHERE id = $2',
            [is_guardian, contactId]
        );
        
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Contact not found.' });
        }

        res.json({ success: true, message: 'Guardian status updated successfully.' });
    } catch (err) {
        console.error('Error updating guardian status:', err);
        res.status(500).json({ error: 'Server error updating guardian status.' });
    }
});


// Fetch only contacts marked as guardians (for Guardian / Security settings screen)
app.get('/api/guardians/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const result = await pool.query(
            'SELECT id, user_id, name, phone_number, is_guardian FROM trusted_contacts WHERE user_id = $1 AND is_guardian = true', 
            [userId]
        );
        // Formatted to match what your iOS guardian view expects
        const formatted = result.rows.map(row => ({
            id: row.id,
            guardian_name: row.name,
            guardian_phone: row.phone_number
        }));
        res.json(formatted);
    } catch (err) {
        console.error('Error fetching guardians:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Delete a trusted contact by ID
app.delete('/api/trusted-contacts/:id', async (req, res) => {
    const contactId = req.params.id;
    try {
        const result = await pool.query('DELETE FROM trusted_contacts WHERE id = $1', [contactId]);
        
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Contact not found.' });
        }

        res.json({ success: true, message: 'Contact deleted successfully.' });
    } catch (err) {
        console.error('Error deleting trusted contact:', err);
        res.status(500).json({ error: 'Server error deleting contact.' });
    }
});

// Passcode Management Route
app.put('/api/user/passcode', async (req, res) => {
    const { userId, passcode } = req.body;

    if (!userId || !passcode) {
        return res.status(400).json({ error: 'userId and passcode are required.' });
    }

    try {
        await pool.query(
            'UPDATE users SET passcode = $1 WHERE id = $2',
            [passcode, userId]
        );

        res.json({
            success: true,
            message: 'Passcode updated successfully.'
        });
    } catch (err) {
        console.error('Error updating passcode:', err);
        res.status(500).json({ error: 'Server error updating passcode.' });
    }
});

// POST /api/trusted-contacts/bulk (Single source of truth insert)
app.post('/api/trusted-contacts/bulk', async (req, res) => {
    try {
        const { userId, contacts } = req.body;
        
        if (!userId || !contacts || !Array.isArray(contacts)) {
            return res.status(400).json({ error: "Invalid payload format" });
        }

        for (const contact of contacts) {
            const isGuardian = contact.is_guardian || false;

            await pool.query(
                `INSERT INTO trusted_contacts (user_id, name, phone_number, is_guardian) 
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (user_id, phone_number) 
                 DO UPDATE SET name = EXCLUDED.name, is_guardian = EXCLUDED.is_guardian`,
                [userId, contact.name, contact.phone_number, isGuardian]
            );
        }

        res.status(201).json({ success: true, message: "Contacts saved successfully" });
    } catch (err) {
        console.error("❌ Database error during bulk save:", err);
        res.status(500).json({ error: err.message });
    }
});

// Toggle Guardian Mode Route
app.put('/api/user/toggle-guardian-mode', async (req, res) => {
    const { userId, isGuardianEnabled } = req.body;

    if (userId === undefined || isGuardianEnabled === undefined) {
        return res.status(400).json({ error: 'userId and isGuardianEnabled status are required.' });
    }

    try {
        await pool.query(
            'UPDATE users SET is_guardian_mode_enabled = $1 WHERE id = $2',
            [isGuardianEnabled, userId]
        );

        res.json({
            success: true,
            message: `Guardian Mode updated to ${isGuardianEnabled}.`
        });
    } catch (err) {
        console.error('Error updating guardian mode toggle:', err);
        res.status(500).json({ error: 'Server error updating guardian mode status.' });
    }
});

// ----------------------------------------------------
// 7. Start Express Server
// ----------------------------------------------------
app.listen(PORT, () => {
    console.log(`Mobile Call Shield Server running on port ${PORT}`);
});