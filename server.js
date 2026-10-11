const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');

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
// Allow requests from your Hostinger domain (and local testing)
const allowedOrigins = [
    'https://mobilecallshield.com',
    'https://www.mobilecallshield.com',
    'http://localhost:3000'
];

app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps, curl, postman)
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
        // Check if user or recovery email already exists
        const existingUser = await pool.query(
            'SELECT * FROM users WHERE phone_number = $1 OR email = $2', 
            [phoneNumber, email]
        );
        
        if (existingUser.rows.length > 0) {
            return res.status(409).json({ error: 'An account with this phone number or email already exists.' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Save user to PostgreSQL database
        const newUser = await pool.query(
            'INSERT INTO users (name, phone_number, email, password_hash, created_at) VALUES ($1, $2, $3, $4, NOW()) RETURNING id, name, phone_number, email',
            [name || 'User', phoneNumber, email, hashedPassword]
        );

        res.status(201).json({
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
// 4. Contacts CRUD API (Used by iOS ContactSyncManager & Web)
// ----------------------------------------------------

// GET /api/contacts?userId=42
app.get('/api/contacts', async (req, res) => {
    const userId = req.query.userId;
    if (!userId) {
        return res.status(400).json({ error: 'Missing userId parameter.' });
    }

    try {
        const result = await pool.query(
            'SELECT id, name, phone_number AS "phoneNumber", is_trusted AS "isTrusted" FROM contacts WHERE user_id = $1',
            [userId]
        );
        res.status(200).json(result.rows);
    } catch (err) {
        console.error('Error fetching contacts:', err);
        res.status(500).json({ error: 'Database query error.' });
    }
});

// POST /api/contacts (Add/Shield a new contact)
app.post('/api/contacts', async (req, res) => {
    const { userId, name, phoneNumber, isTrusted } = req.body;

    if (!userId || !phoneNumber) {
        return res.status(400).json({ error: 'userId and phoneNumber are required.' });
    }

    try {
        const result = await pool.query(
            'INSERT INTO contacts (user_id, name, phone_number, is_trusted, created_at) VALUES ($1, $2, $3, $4, NOW()) RETURNING id, name, phone_number AS "phoneNumber", is_trusted AS "isTrusted"',
            [userId, name, phoneNumber, isTrusted ?? true]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('Error saving contact:', err);
        res.status(500).json({ error: 'Failed to save contact.' });
    }
});

// ----------------------------------------------------
// 5. Beta Tester Portal Error Logging Endpoint
// ----------------------------------------------------
app.post('/api/tester-feedback', async (req, res) => {
    const { testerName, device, errorDetails } = req.body;

    try {
        console.log(`\n--- [BETA TESTER FEEDBACK] ---`);
        console.log(`Tester: ${testerName} | Device: ${device}`);
        console.log(`Details: ${errorDetails}\n`);

        // Save to PostgreSQL if table exists
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
// 6. Twilio Voice Webhook (Incoming Call Screening)
// ----------------------------------------------------
app.post('/voice', (req, res) => {
    const twiml = `<?xml version="1.0" encoding="UTF-8"?>
    <Response>
        <Say voice="alice">Hello. This number is protected by Mobile Call Shield. Please speak your name or passphrase after the tone to connect your call.</Say>
        <Record maxLength="10" action="/process-passphrase" />
    </Response>`;
    
    res.type('text/xml');
    res.send(twiml);
});

// ----------------------------------------------------
// 7. Start Express Server
// ----------------------------------------------------
app.listen(PORT, () => {
    console.log(`Mobile Call Shield Server running on port ${PORT}`);
});