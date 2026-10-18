const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const twilio = require('twilio');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;

// ----------------------------------------------------
// 1. Database Connection (PostgreSQL on Render)
// ----------------------------------------------------
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

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

// ==========================================
// 3. SECURITY MANAGEMENT ENDPOINTS (PIN, Passcode, Guardian Code)
// ==========================================

app.put('/api/user/update-owner-pin', async (req, res) => {
    const { userId, currentPin, newPin } = req.body;

    if (!userId || !currentPin || !newPin) {
        return res.status(400).json({ error: 'User ID, current PIN, and new PIN are required.' });
    }

    try {
        const userResult = await pool.query('SELECT pin FROM users WHERE id = $1', [userId]);
        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }

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
        if (userCheck.rows.length === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }

        const currentDbPin = userCheck.rows[0].pin || '1234';
        if (currentDbPin !== pin) {
            return res.status(401).json({ error: 'Incorrect Owner PIN.' });
        }

        await pool.query('UPDATE users SET passcode = $1 WHERE id = $2', [newPasscode, userId]);

        res.status(200).json({
            success: true,
            message: 'Screening Passcode Phrase updated successfully!'
        });
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
        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }

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
// 5. User Authentication Routes
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