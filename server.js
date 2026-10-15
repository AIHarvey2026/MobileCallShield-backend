const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const twilio = require('twilio');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;

const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT || 587,
    secure: false,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

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

// Subscription Sync
app.post('/api/subscription/sync', async (req, res) => {
    const { userId, originalTransactionId, expirationDate, isTrial } = req.body;

    if (!userId) {
        return res.status(400).json({ error: 'User ID is required.' });
    }

    try {
        await pool.query(
            `UPDATE users 
             SET subscription_status = $1, 
                 original_transaction_id = $2
             WHERE id = $3`,
            [isTrial ? 'trialing' : 'active', originalTransactionId, userId]
        );

        res.json({ success: true, message: 'Subscription status synced with Apple StoreKit.' });
    } catch (err) {
        console.error('Error syncing StoreKit transaction:', err);
        res.status(500).json({ error: 'Server error syncing subscription.' });
    }
});

// ----------------------------------------------------
// 3. User Authentication Routes
// ----------------------------------------------------
app.post('/api/auth/register', authLimiter, async (req, res) => {
    const { name, phoneNumber, email, password, pin, passcode } = req.body;

    if (!phoneNumber || !password || !email || !pin) {
        return res.status(400).json({ error: 'Phone number, email, password, and PIN are required.' });
    }

    try {
        const existingUser = await pool.query(
            'SELECT * FROM users WHERE owner_phone = $1 OR email = $2', 
            [phoneNumber, email]
        );

        if (existingUser.rows.length > 0) {
            return res.status(409).json({ error: 'An account with this phone number or email already exists.' });
        }

        const userPasscode = passcode || '1234';
        
        const trialEnd = new Date();
        trialEnd.setDate(trialEnd.getDate() + 14);

        const newUser = await pool.query(
            `INSERT INTO users (user_name, owner_phone, email, password, pin, passcode, subscription_status, trial_ends_at, created_at) 
             VALUES ($1, $2, $3, $4, $5, $6, 'trialing', $7, NOW()) 
             RETURNING id, user_name, owner_phone, email, passcode, subscription_status`,
            [name || email, phoneNumber, email, password, pin, userPasscode, trialEnd]
        );

        const formattedTrialEnd = trialEnd.toLocaleDateString('en-US', {
            weekday: 'long',
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        });

        const mailOptions = {
            from: '"Senior Scam Shield" <support@mobilecallshield.com>',
            to: email,
            subject: 'Welcome to Senior Scam Shield! Your 14-Day Free Trial Has Started',
            html: `
                <div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 8px;">
                    <h2 style="color: #2563eb; margin-top: 0;">Welcome to Senior Scam Shield, ${name || 'Friend'}!</h2>
                    <p>Your account has been successfully created, and your <strong>14-day free trial</strong> is now active.</p>
                    
                    <div style="background-color: #f8fafc; padding: 15px; border-radius: 6px; margin: 20px 0; border-left: 4px solid #2563eb;">
                        <p style="margin: 0; font-size: 15px;"><strong>Trial End Date:</strong> ${formattedTrialEnd}</p>
                        <p style="margin: 5px 0 0 0; font-size: 13px; color: #64748b;">You will have full access to call screening, trusted contacts, and voicemail playback during your trial without any charges.</p>
                    </div>

                    <p>If you have any questions or need assistance setting up your phone forwarding, feel free to reply directly to this email or visit our support portal.</p>
                    
                    <p style="margin-top: 30px; font-size: 14px; color: #64748b;">Stay protected,<br><strong>The Senior Scam Shield Team</strong></p>
                </div>
            `
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('Error sending trial welcome email:', error);
            } else {
                console.log('Trial welcome email sent:', info.response);
            }
        });

        res.status(201).json({
            success: true,
            message: 'User registered successfully with a 14-day free trial!',
            user: {
                id: newUser.rows[0].id,
                name: newUser.rows[0].user_name,
                phoneNumber: newUser.rows[0].owner_phone,
                email: newUser.rows[0].email,
                passcode: newUser.rows[0].passcode,
                subscriptionStatus: newUser.rows[0].subscription_status
            }
        });
    } catch (err) {
        console.error('Error during registration:', err);
        res.status(500).json({ error: 'Server error creating user account.' });
    }
});

// Login
app.post('/api/auth/login', authLimiter, async (req, res) => {
    const { email, password } = req.body;

    console.log(`[Login Attempt] Email received: "${email}" | Password received: "${password}"`);

    try {
        const result = await pool.query(
            'SELECT * FROM users WHERE email = $1', 
            [email]
        );

        if (result.rows.length === 0) {
            console.log(`[Login Error] User not found in database for email: "${email}"`);
            return res.status(401).json({ error: 'Invalid credentials: User not found.' });
        }

        const user = result.rows[0];
        console.log(`[Login Debug] User found! Checking password...`);

        const match = (password === user.password) || await bcrypt.compare(password, user.password).catch(() => false);

        if (!match) {
            console.log(`[Login Error] Password mismatch for email: "${email}"`);
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
// Subscription & Twilio Number Provisioning Endpoint
// ----------------------------------------------------
app.post('/api/subscription/activate', async (req, res) => {
    const { userId, areaCode } = req.body;

    if (!userId) {
        return res.status(400).json({ error: 'User ID is required.' });
    }

    try {
        const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

        const availableNumbers = await twilioClient.availablePhoneNumbers('US')
            .local
            .list({ areaCode: areaCode || undefined, limit: 1 });

        if (availableNumbers.length === 0) {
            return res.status(404).json({ error: 'No available phone numbers found for this area code.' });
        }

        const targetNumber = availableNumbers[0].phoneNumber;

        const purchasedNumber = await twilioClient.incomingPhoneNumbers.create({
            phoneNumber: targetNumber,
            voiceUrl: 'https://mobilecallshield-backend.onrender.com/voice',
            voiceMethod: 'POST'
        });

        await pool.query(
            'UPDATE users SET subscription_status = $1 WHERE id = $2',
            ['active', userId]
        );

        await pool.query(
            `INSERT INTO phone_numbers (user_id, phone_number, is_active) 
             VALUES ($1, $2, true)
             ON CONFLICT DO NOTHING`,
            [userId, purchasedNumber.phoneNumber]
        );

        console.log(`[Subscription Activated] User ID ${userId} assigned Twilio number: ${purchasedNumber.phoneNumber}`);

        res.json({
            success: true,
            assignedPhoneNumber: purchasedNumber.phoneNumber,
            message: 'Subscription activated and phone number successfully assigned!'
        });

    } catch (err) {
        console.error('Error provisioning Twilio phone number:', err);
        res.status(500).json({ error: 'Failed to provision phone number from Twilio.' });
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
            SELECT u.id, u.owner_phone, u.is_call_shield_enabled 
            FROM phone_numbers pn
            JOIN users u ON pn.user_id = u.id
            WHERE pn.phone_number = $1 AND pn.is_active = true
        `, [twilioNumber]);

        if (userResult.rows.length > 0) {
            const user = userResult.rows[0];

            if (user.is_call_shield_enabled !== true) {
                console.log(`[Call Shield Disabled] Direct dialing owner phone: ${user.owner_phone}`);
                
                await pool.query(
                    'INSERT INTO call_logs (user_id, caller_phone, called_phone, status) VALUES ($1, $2, $3, $4)',
                    [user.id, req.body.From, twilioNumber, 'DIRECT_DIAL']
                ).catch(err => console.error('Error logging direct dial:', err));

                twiml.dial(user.owner_phone);
                res.type('text/xml');
                return res.send(twiml.toString());
            }

            console.log(`[Call Shield Enabled] Starting screening for ${req.body.From}`);
            const gather = twiml.gather({
                input: 'speech',
                action: '/process-passphrase',
                method: 'POST',
                timeout: 8,
                speechTimeout: 'auto'
            });
            
            gather.say({ voice: 'Polly.Joanna-Neural' }, 'Hello! This number is protected by Mobile Call Shield. Please state your name or passcode after the tone.');

            res.type('text/xml');
            return res.send(twiml.toString());
        }
    } catch (err) {
        console.error('Error checking shield status on incoming call:', err);
    }

    twiml.say({ voice: 'Polly.Joanna-Neural' }, 'No active account found for this phone number. Goodbye.');
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
            twiml.say({ voice: 'Polly.Joanna-Neural' }, 'No active account found for this phone number.');
            twiml.hangup();
            res.type('text/xml');
            return res.send(twiml.toString());
        }

        const user = userResult.rows[0];
        const forwardNumber = user.owner_phone;
        const userPasscode = (user.passcode || '1234').toLowerCase().trim();

        if (spokenPassphrase.length > 0 && spokenPassphrase.includes(userPasscode)) {
            await pool.query(
                'INSERT INTO call_logs (user_id, caller_phone, called_phone, status) VALUES ($1, $2, $3, $4)',
                [user.id, req.body.From, twilioNumber, 'PASSED_PASSCODE']
            ).catch(err => console.error('Error logging passed passcode:', err));

            twiml.say({ voice: 'Polly.Joanna-