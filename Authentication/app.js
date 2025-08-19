const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const bodyParser = require('body-parser');
const cron = require('node-cron');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const methodOverride = require('method-override');
// const fetch = require("node-fetch");

const cors = require("cors");
require('dotenv').config();

const connectDB = require('./database');
const User = require('./models/User');
const app = express();
const PORT = process.env.PORT || 3000;
// Removed LOGIN_LOG_FILE as fs.appendFile is not suitable for Render's ephemeral filesystem.
// const LOGIN_LOG_FILE = path.join(__dirname, 'login_log.txt');
connectDB();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors({ origin: "http://localhost:1234", credentials: true }));
app.use(express.json());

// --- CRITICAL FIX 1: Trust proxy for session cookies to work with Render's HTTPS ---
app.set('trust proxy', 1); // Trust the first proxy in front of your app (Render's load balancer)

app.use(methodOverride('_method'));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI, // <--- IMPORTANT: Ensure this matches your .env / Render env var
        collectionName: 'sessions',
        ttl: 14 * 24 * 60 * 60,
        autoRemove: 'interval',
        autoRemoveInterval: 10
    }),
    cookie: {
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // Set secure: true ONLY in production (HTTPS)
        sameSite: 'lax' // <--- CRITICAL FIX 2: Add sameSite to prevent cookie issues
    }
}));
app.use(express.static(path.join(__dirname, 'public')));


async function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) { // Check if req.session exists and has userId
        try {
            const user = await User.findById(req.session.userId).select('username');
            if (user) {
                req.user = {
                    id: user._id,
                    username: user.username
                };
                next();
            } else {
                console.log("User ID in session not found in DB. Destroying session.");
                req.session.destroy(() => {
                    res.redirect('/login');
                });
            }
        } catch (error) {
            console.error('Error in isAuthenticated middleware:', error);
            req.session.destroy(() => {
                res.redirect('/login');
            });
        }
    } else {
        res.redirect('/login');
    }
}


app.get('/', (req, res) => res.redirect('/login'));

app.get('/signup', (req, res) => {
    res.render('signup', { error1: null, error2: null });
});

app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailRegex.test(username)) {
      return res.render('signup', { error1: 'Invalid email format', error2: null });
    }

    if (password.length < 6) {
        return res.render('signup', { error1: null, error2: 'Password must be at least 6 characters long' });
    }

    try {
        const newUser = new User({ username, password });
        await newUser.save();

        const now = new Date();
        // Logging directly to console for Render
        console.log(`[Signup Log] ${username} Signed up at ${now.toLocaleString()}`);

        req.session.username = newUser.username;
        req.session.userId = newUser._id;

        return res.redirect("http://localhost:1234");

    } catch (error) {
        console.error('Error during signup:', error);
        if (error.code === 11000) {
            return res.render('signup', { error1: 'Email already exists.', error2: null });
        }
        res.status(500).render('signup', { error1: 'Server error during signup.', error2: null });
    }
});

app.get('/login', (req, res) => {
     res.render('login', { error3: null, error4: null });
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username });

        if (!user) {
            return res.render('login', { error3: 'Invalid Email', error4: null });
        }

        const match = await user.comparePassword(password);
        if (!match) {
            return res.render('login', { error3: null, error4: 'Wrong password' });
        }

        req.session.username = user.username;
        req.session.userId = user._id;

        const now = new Date();
        // Logging directly to console for Render
        console.log(`[Login Log] ${username} logged in at ${now.toLocaleString()}`);

         return res.redirect("http://localhost:1234");

    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).render('login', { error3: 'Server error during login', error4: null });
    }
});


app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).send('Could not log out.');
        }
        res.redirect('/login');
    });
});


app.get('/forgot', (req, res) => {
    res.render('forgot', { error: null, message: null });
});

app.post('/forgot', async (req, res) => {
    const { username } = req.body;

    try {
        const user = await User.findOne({ username });

        if (!user) {
            return res.render('forgot', { error: 'Email not found', message: null });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiry = Date.now() + 5 * 60 * 1000;

        await User.updateOne(
            { _id: user._id },
            { otpToken: otp, otpExpires: expiry, allowReset: false }
        );

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.GMAIL_USER,
                pass: process.env.GMAIL_PASS
            }
        });

        transporter.sendMail({
            from: process.env.EMAIL_FROM || '"StudyCloud" <ad2421853@gmail.com>',
            to: user.username,
            subject: 'Your OTP to Reset Password',
            html: `<h3>Your OTP: <b>${otp}</b></h3><p>It is valid for 5 minutes.</p>`
        }, (err, info) => {
            if (err) {
                console.error('❌ Email error:', err);
                return res.render('forgot', { error: 'Failed to send OTP. Try again.', message: null });
            } else {
                console.log('✅ Email sent:', info.response);
                return res.render('verify', { username: user.username, error: null });
            }
        });
    } catch (error) {
        console.error('Error during forgot password request:', error);
        res.status(500).render('forgot', { error: 'Server error. Try again.', message: null });
    }
});

app.post('/verify', async (req, res) => {
    const { username, otp } = req.body;

    try {
        const user = await User.findOne({ username });

        if (!user || user.otpToken !== otp || user.otpExpires < Date.now()) {
            return res.render('verify', { username, error: 'Invalid or expired OTP' });
        }

        await User.updateOne(
            { _id: user._id },
            { allowReset: true, otpToken: null, otpExpires: null }
        );

        res.render('reset', { username, error: null, message: null });
    } catch (error) {
        console.error('Error during OTP verification:', error);
        res.status(500).render('verify', { username, error: 'Server error during verification.' });
    }
});

app.post('/reset', async (req, res) => {
    const { username, password, confirmPassword } = req.body;

    try {
        const user = await User.findOne({ username });

        if (!user || !user.allowReset) {
            return res.render('reset', { username, error: 'Session expired or unauthorized. Please request OTP again.', message: null });
        }

        if (password !== confirmPassword) {
            return res.render('reset', { username, error: 'Passwords do not match.', message: null });
        }

        if (password.length < 6) {
            return res.render('reset', { username, error: 'Password must be at least 6 characters.', message: null });
        }

        user.password = password;
        user.allowReset = false;
        await user.save();

        res.render('reset', { username: null, error: null, message: '✅ Password successfully changed! You can now log in.' });
    } catch (error) {
        console.error('Error during password reset:', error);
        res.status(500).render('reset', { username, error: 'Server error during password reset.', message: null });
    }
});

app.get("/api/restaurants", async (req, res) => {
  try {
    const response = await fetch(
      "https://www.swiggy.com/dapi/restaurants/list/v5?lat=28.4608649&lng=77.493317&is-seo-homepage-enabled=true&page_type=DESKTOP_WEB_LISTING",
      {
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
          "Accept": "application/json, text/plain, */*",
          "Referer": "https://www.swiggy.com/",
          "Origin": "https://www.swiggy.com",
        },
      }
    );
    const data = await response.json();
    res.json(data);
  } catch (error) {
    console.error("Error fetching Swiggy API:", error);
    res.status(500).json({ error: "Failed to fetch data" });
  }
});


app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
    if (process.env.MONGODB_URI) {
        try {
            const uriParts = new URL(process.env.MONGODB_URI);
            const host = uriParts.hostname;
            const dbName = uriParts.pathname ? uriParts.pathname.substring(1) : 'default';
            console.log(`Connected to MongoDB: Host: ${host}, DB: ${dbName}`);
        } catch (e) {
            console.log(`Connected to MongoDB (URI details hidden)`);
        }
    } else {
        console.log(`MongoDB URI not set in environment variables.`);
    }
});
