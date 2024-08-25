const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const db = require('../db');
const logger = require('../utils/logger');
const { sendEmail } = require('../utils/mailer');
const PasswordValidator = require('password-validator');
const validator = require('validator');
const router = express.Router();

// Create a password schema
const passwordSchema = new PasswordValidator();
passwordSchema
    .is().min(8)                                    // Minimum length 8
    .is().max(100)                                  // Maximum length 100
    .has().uppercase()                             // Must have uppercase letters
    .has().lowercase()                             // Must have lowercase letters
    .has().digits()                                // Must have digits
    .has().not().spaces()                          // Should not have spaces
    .is().not().oneOf(['Passw0rd', 'Password123']); // Blacklist these values

// Sign-Up Route
router.post('/signup', async (req, res) => {
    const { email, password } = req.body;
    try {
        // Validate email format
        if (!validator.isEmail(email)) {
            logger.warn('Invalid email format', { email });
            return res.status(400).json({ error: 'Invalid email format' });
        }

        // Check password strength
        const passwordValidationResult = passwordSchema.validate(password, { list: true });
        if (passwordValidationResult.length > 0) {
            logger.warn('Password validation failed', { email, errors: passwordValidationResult });
            return res.status(400).json({ error: `Password does not meet the requirements: ${passwordValidationResult.join(', ')}` });
        }

        // Check if the user already exists
        const userExists = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userExists.rows.length > 0) {
            logger.warn('User already exists', { email });
            return res.status(400).json({ error: 'User already exists' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Generate a verification token
        const verificationToken = crypto.randomBytes(32).toString('hex');

        // Store the user in the database with the verification token
        await db.query('INSERT INTO users (email, password, verification_token, verified) VALUES ($1, $2, $3, false)', [email, hashedPassword, verificationToken]);

        // Send a verification email
        const verificationUrl = `${process.env.BASE_URL}/auth/verify-email?token=${verificationToken}`;
        await sendEmail(email, 'Email Verification', `Please verify your email by clicking on the following link: ${verificationUrl}`);

        logger.info('User registered successfully, verification email sent', { email });
        res.status(201).json({ message: 'User registered successfully. Please check your email to verify your account.' });
    } catch (err) {
        logger.error('Error during sign-up', { error: err.message, email });
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Sign-In Route
router.post('/signin', async (req, res) => {
    const { email, password } = req.body;
    try {
        // Validate email format
        if (!validator.isEmail(email)) {
            logger.warn('Invalid email format', { email });
            return res.status(400).json({ error: 'Invalid email format' });
        }

        // Check if the user exists
        const userResult = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = userResult.rows[0];
        if (!user) {
            logger.warn('User not found', { email });
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        // Check if the user is verified
        if (!user.verified) {
            // Generate a new verification token
            const verificationToken = crypto.randomBytes(32).toString('hex');
            await db.query('UPDATE users SET verification_token = $1 WHERE email = $2', [verificationToken, email]);

            // Send a verification email
            const verificationUrl = `${process.env.BASE_URL}/auth/verify-email?token=${verificationToken}`;
            await sendEmail(email, 'Email Verification', `Please verify your email by clicking on the following link: ${verificationUrl}`);

            logger.info('Verification email resent', { email });
            return res.status(400).json({ error: 'Email not verified. A new verification email has been sent.' });
        }

        // Compare the password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            logger.warn('Invalid password attempt', { email });
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        // Generate a JWT token
        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        // Generate a refresh token
        const refreshToken = jwt.sign({ id: user.id }, process.env.REFRESH_SECRET, { expiresIn: '7d' });

        // Set the tokens in HTTP-only cookies
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 3600000, // 1 hour
        });
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 604800000, // 7 days
        });

        logger.info('User signed in successfully', { email });
        res.status(200).json({ token, refreshToken });
    } catch (err) {
        logger.error('Error during sign-in', { error: err.message, email });
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Refresh Token Route
router.post('/refresh-token', (req, res) => {
    const { refreshToken } = req.cookies;
    if (!refreshToken) {
        logger.warn('No refresh token provided');
        return res.sendStatus(401);
    }

    jwt.verify(refreshToken, process.env.REFRESH_SECRET, (err, user) => {
        if (err) {
            logger.warn('Invalid refresh token', { error: err.message });
            return res.sendStatus(403);
        }

        const newToken = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.cookie('token', newToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 3600000, // 1 hour
        });

        logger.info('Token refreshed successfully', { userId: user.id });
        res.status(200).json({ token: newToken });
    });
});

// Verify Email Route
router.get('/verify-email', async (req, res) => {
    const { token } = req.query;
    try {
        // Find the user with the verification token
        const result = await db.query('SELECT * FROM users WHERE verification_token = $1', [token]);
        if (result.rows.length === 0) {
            logger.warn('Invalid or expired verification token', { token });
            return res.status(400).json({ error: 'Invalid or expired verification token' });
        }

        // Update the user's verification status
        const user = result.rows[0];
        await db.query('UPDATE users SET verified = true, verification_token = NULL WHERE id = $1', [user.id]);

        logger.info('Email verified successfully', { userId: user.id });
        res.status(200).json({ message: 'Email verified successfully' });
    } catch (err) {
        logger.error('Error during email verification', { error: err.message, token });
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;
