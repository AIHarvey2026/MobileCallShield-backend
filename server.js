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
// 3. User Authentication Routes
// ----------------------------------------------------

// POST /api/auth/register (User Sign Up from Hostinger or Mobile App)
app.post('/api/auth/register', async (req, res) => {
    const { name, phoneNumber, email, password } = req.body;

    if (!phoneNumber || !password || !email) {
        return res.status(400).json({ error: 'Phone number, email, and password are required.' });
    }

    try {
        const existingUser = await pool.query(
            'SELECT * FROM users WHERE phone_number = $1 OR email = $2', 
            [phoneNumber, email]
        );
        
        if (existingUser.rows.length > 0) {
            return res.status(409).json({ error: 'An account with this phone number or email already exists.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await pool.query(
            'INSERT INTO users (name, phone_number, email, password_hash, created_at) VALUES ($1, $2, $3, $4, NOW()) RETURNING id, name, phone_number, email',
            [name || 'User', phoneNumber, email, hashedPassword]
        );

        res.status(201).json({
            success: true,
            message: 'User registered successfully!',
            user: newUser.rows[0]
        });
    } catch (err) {
        console.error('Error during registration:', err);
        res.status(500).json({ error: 'Server error creating user account.' });
    }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
    const { phoneNumber, password } = req.body;

    try {
        const result = await pool.query('SELECT * FROM users WHERE phone_number = $1', [phoneNumber]);
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid phone number or password.' });
        }

        const user = result.rows[0];
        const match = await bcrypt.compare(password, user.password_hash);

        if (!match) {
            return res.status(401).json({ error: 'Invalid phone number or password.' });
        }

        res.status(200).json({
            success: true,
            message: 'Login successful!',
            user: {
                id: user.id,
                name: user.name,
                phoneNumber: user.phone_number,
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

// Initial Call Greeting & Speech Gathering Endpoint
app.post('/voice', async (req, res) => {
    const twilioNumber = req.body.To;
    console.log(`[Twilio Call] Incoming call to Twilio number: ${twilioNumber}`);

    const twiml = new twilio.twiml.VoiceResponse();

    const gather = twiml.gather({
        input: 'speech',
        action: '/process-passphrase',
        method: 'POST',
        timeout: 5,
        speechTimeout: 'auto'
    });

    gather.say({ voice: 'alice' }, 'Hello. This number is protected by Mobile Call Shield. Please state your name or passcode after the tone.');

    twiml.say({ voice: 'alice' }, 'We did not receive any response. Goodbye.');
    twiml.hangup();

    res.type('text/xml');
    res.send(twiml.toString());
});

// Passphrase Processing & Dynamic Forwarding Endpoint
app.post('/process-passphrase', async (req, res) => {
    const twiml = new twilio.twiml.VoiceResponse();
    const spokenPassphrase = (req.body.SpeechResult || '').toLowerCase().trim();

    console.log(`[Twilio Call] Caller said: "${spokenPassphrase}"`);

    try {
        // Query using the correct columns: owner_phone and passcode
        const userResult = await pool.query('SELECT owner_phone, passcode FROM users ORDER BY id ASC LIMIT 1');
        
        if (userResult.rows.length === 0) {
            twiml.say({ voice: 'alice' }, 'No user account found to route this call.');
            twiml.hangup();
            res.type('text/xml');
            return res.send(twiml.toString());
        }

        const user = userResult.rows[0];
        const forwardNumber = user.owner_phone;
        const userPasscode = (user.passcode || '1234').toLowerCase().trim();

        // Verify if what the caller spoke matches the user's custom passcode
        if (spokenPassphrase.length > 0 && spokenPassphrase.includes(userPasscode)) {
            twiml.say({ voice: 'alice' }, 'Passcode accepted. Connecting your call now.');
            twiml.dial(forwardNumber);
        } else {
            twiml.say({ voice: 'alice' }, 'Passcode not recognized. Access denied.');
            twiml.hangup();
        }
    } catch (err) {
        console.error('Database lookup error during passcode verification:', err);
        twiml.say({ voice: 'alice' }, 'An internal error occurred processing your call.');
        twiml.hangup();
    }

    res.type('text/xml');
    res.send(twiml.toString());
});

// ----------------------------------------------------
// 6. Start Express Server
// ----------------------------------------------------
app.listen(PORT, () => {
    console.log(`Mobile Call Shield Server running on port ${PORT}`);
});