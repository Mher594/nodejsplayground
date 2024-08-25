const request = require('supertest');
const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const authRouter = require('../routes/auth');

// Import the modules to mock
const db = require('../db');
const bcrypt = require('bcrypt');
const { sendEmail } = require('../utils/mailer');
const logger = require('../utils/logger');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

// Mock the modules
jest.mock('../db');
jest.mock('../utils/mailer');
jest.mock('../utils/logger');
jest.mock('bcrypt', () => ({
    hash: jest.fn(),
    compare: jest.fn()
}));
jest.mock('jsonwebtoken', () => ({
    sign: jest.fn(),
    verify: jest.fn()
}));

app.use(bodyParser.json());
app.use(cookieParser());
app.use('/auth', authRouter);

describe('Auth Routes', () => {
    // Test sign-up route
    describe('POST /auth/signup', () => {
        beforeEach(() => {
            // Clear all instances and calls to constructor and all methods:
            db.query.mockClear();
            bcrypt.hash.mockClear();
            sendEmail.mockClear();
            logger.warn.mockClear();
            logger.info.mockClear();
            logger.error.mockClear();
        });

        it('should return error for invalid email format', async () => {
            const response = await request(app)
                .post('/auth/signup')
                .send({
                    email: 'invalid-email',
                    password: 'Test1234'
                });

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('Invalid email format');
        });

        it('should return error for weak password', async () => {
            const response = await request(app)
                .post('/auth/signup')
                .send({
                    email: 'testuser2@example.com',
                    password: '123'
                });

            expect(response.status).toBe(400);
            expect(response.body.error).toMatch("Password does not meet the requirements");
        });

        it('should call db.query with correct arguments when sign-up is successful', async () => {
            // Setup mock return values
            db.query.mockResolvedValueOnce({ rows: [] }); // No user found
            bcrypt.hash.mockResolvedValue('hashedPassword'); // Return a dummy hashed password
            sendEmail.mockResolvedValue(true); // Mock successful email sending

            // Make a request to the sign-up route
            const response = await request(app)
                .post('/auth/signup')
                .send({
                    email: 'validuser@example.com',
                    password: 'ValidPassword123'
                });

            // Check if db.query was called with the correct arguments
            expect(db.query).toHaveBeenCalledWith(
                'INSERT INTO users (email, password, verification_token, verified) VALUES ($1, $2, $3, false)',
                ['validuser@example.com', 'hashedPassword', expect.any(String)]
            );

            // Check if sendEmail was called with the correct arguments
            const verificationUrl = `${process.env.BASE_URL}/auth/verify-email?token=`;
            expect(sendEmail).toHaveBeenCalledWith(
                'validuser@example.com',
                'Email Verification',
                expect.stringContaining(verificationUrl) // Check if the email contains the verification URL
            );

            // Optionally, check other aspects of the response
            expect(response.status).toBe(201);
            expect(response.body.message).toBe('User registered successfully. Please check your email to verify your account.');
        });
    });

    // Test sign-in route
    describe('POST /auth/signin', () => {
        beforeEach(() => {
            // Clear all instances and calls to constructor and all methods:
            db.query.mockClear();
            bcrypt.hash.mockClear();
            bcrypt.compare.mockClear();
            sendEmail.mockClear();
            logger.warn.mockClear();
            logger.info.mockClear();
            logger.error.mockClear();
            jwt.sign.mockClear();
        });

        it('should return error for invalid email format', async () => {
            const response = await request(app)
                .post('/auth/signin')
                .send({
                    email: 'invalid-email',
                    password: 'Test1234'
                });

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('Invalid email format');
        });

        it('should return error if user is not found during sign-in', async () => {
            // Mock db.query to return no rows
            db.query.mockResolvedValueOnce({ rows: [] }); // No user found

            const response = await request(app)
                .post('/auth/signin')
                .send({
                    email: 'nonexistentuser@example.com',
                    password: 'SomePassword123'
                });

            // Check if the response status code is 400
            expect(response.status).toBe(400);

            // Check if the response body has the correct error message
            expect(response.body.error).toBe('Invalid credentials');

            // Check if the logger's warn method was called with the expected message
            expect(logger.warn).toHaveBeenCalledWith('User not found', { email: 'nonexistentuser@example.com' });
        });

        it('should return error for invalid password attempt', async () => {
            // Mock db.query to return a user with a hashed password
            db.query.mockResolvedValueOnce({
                rows: [{
                    email: 'user@example.com',
                    password: await bcrypt.hash('ValidPassword123', 10), // Example hashed password
                    verified: true,
                    id: 'user123'
                }]
            });

            // Mock bcrypt.compare to return false for the password comparison
            bcrypt.compare.mockResolvedValue(false);

            const response = await request(app)
                .post('/auth/signin')
                .send({
                    email: 'user@example.com',
                    password: 'InvalidPassword123' // Incorrect password
                });

            // Check if the response status code is 400
            expect(response.status).toBe(400);

            // Check if the response body has the correct error message
            expect(response.body.error).toBe('Invalid credentials');

            // Check if the logger's warn method was called with the expected message
            expect(logger.warn).toHaveBeenCalledWith('Invalid password attempt', { email: 'user@example.com' });
        });

        it('should return error if user is not verified and send a verification email', async () => {
            // Mock db.query to return a user who is not verified
            db.query.mockResolvedValueOnce({
                rows: [{
                    email: 'unverifieduser@example.com',
                    password: await bcrypt.hash('ValidPassword123', 10), // Example hashed password
                    verified: false,
                    id: 'user123'
                }]
            });

            // Mock bcrypt.compare to return true for the valid password
            bcrypt.compare.mockResolvedValue(true);

            // Mock the sendEmail function
            sendEmail.mockResolvedValue(true); // Ensure no email sending is actually performed

            const response = await request(app)
                .post('/auth/signin')
                .send({
                    email: 'unverifieduser@example.com',
                    password: 'ValidPassword123' // Correct password
                });

            // Check if the response status code is 400
            expect(response.status).toBe(400);

            // Check if the response body has the correct error message
            expect(response.body.error).toBe('Email not verified. A new verification email has been sent.');

            // Check if the db.query method was called with the expected arguments
            expect(db.query).toHaveBeenCalledWith(
                'SELECT * FROM users WHERE email = $1',
                ['unverifieduser@example.com']
            );

            // Check if the sendEmail function was called with the correct arguments
            const verificationUrl = `${process.env.BASE_URL}/auth/verify-email?token=`;
            expect(sendEmail).toHaveBeenCalledWith(
                'unverifieduser@example.com',
                'Email Verification',
                expect.stringContaining(verificationUrl) // Check if the email contains the verification URL
            );

            // Check if the logger's info method was called with the expected message
            expect(logger.info).toHaveBeenCalledWith('Verification email resent', { email: 'unverifieduser@example.com' });
        });

        it('should sign in user and set cookies if credentials are valid and user is verified', async () => {
            // Mock db.query to return a verified user
            db.query.mockResolvedValueOnce({
                rows: [{
                    email: 'verifieduser@example.com',
                    password: await bcrypt.hash('ValidPassword123', 10), // Example hashed password
                    verified: true,
                    id: 'user123'
                }]
            });

            // Mock bcrypt.compare to return true for the valid password
            bcrypt.compare.mockResolvedValue(true);

            // Mock JWT sign method to return specific tokens
            const accessToken = 'mockAccessToken';
            const refreshToken = 'mockRefreshToken';
            jwt.sign
                .mockReturnValueOnce(accessToken)  // First call for the access token
                .mockReturnValueOnce(refreshToken); // Second call for the refresh token

            const response = await request(app)
                .post('/auth/signin')
                .send({
                    email: 'verifieduser@example.com',
                    password: 'ValidPassword123'
                });

            // Check that the response status is 200
            expect(response.status).toBe(200);

            // Check that the response body contains the correct tokens
            expect(response.body).toEqual({
                token: accessToken,
                refreshToken: refreshToken
            });

            // Check that the db.query method was called with the expected arguments
            expect(db.query).toHaveBeenCalledWith(
                'SELECT * FROM users WHERE email = $1',
                ['verifieduser@example.com']
            );

            // Check that the bcrypt.compare method was called with the correct arguments
            expect(bcrypt.compare).toHaveBeenCalledWith('ValidPassword123', expect.any(String));

            // Check that the tokens were set as HTTP-only cookies
            expect(response.headers['set-cookie']).toEqual(expect.arrayContaining([
                expect.stringContaining('token=mockAccessToken;'),
                expect.stringContaining('refreshToken=mockRefreshToken;'),
                expect.stringContaining('HttpOnly')
            ]));

            // Check that the logger's info method was called with the expected message
            expect(logger.info).toHaveBeenCalledWith('User signed in successfully', { email: 'verifieduser@example.com' });
        });
    });

    describe('POST /auth/refresh-token', () => {
        beforeEach(() => {
            jest.clearAllMocks();
        });

        // Test case when no refresh token is provided
        it('should return 401 if no refresh token is provided', async () => {
            const response = await request(app)
                .post('/auth/refresh-token')
                .set('Cookie', '') // Simulate request without a refresh token
                .send();

            expect(response.status).toBe(401);
            expect(logger.warn).toHaveBeenCalledWith('No refresh token provided');
        });

        // Test case when the refresh token is invalid
        it('should return 403 if the refresh token is invalid', async () => {
            const invalidToken = 'invalidToken';

            // Mock jwt.verify to simulate an invalid token scenario
            jwt.verify.mockImplementationOnce((token, secret, callback) => {
                callback(new Error('Invalid token'), null);
            });

            const response = await request(app)
                .post('/auth/refresh-token')
                .set('Cookie', `refreshToken=${invalidToken}`) // Simulate request with an invalid refresh token
                .send();

            expect(response.status).toBe(403);
            expect(logger.warn).toHaveBeenCalledWith('Invalid refresh token', { error: 'Invalid token' });
        });

        // Test case when the refresh token is valid and a new token is generated
        it('should generate a new token if the refresh token is valid', async () => {
            const validToken = 'validToken';
            const mockNewToken = 'mockNewToken';
            const validUser = { id: 'user123' };

            jwt.verify.mockImplementationOnce((token, secret, callback) => {
                callback(null, validUser);
            });
            jwt.sign.mockImplementationOnce(() => mockNewToken);

            const response = await request(app)
                .post('/auth/refresh-token')
                .set('Cookie', [`refreshToken=${validToken}`])
                .send();

            expect(response.status).toBe(200);
            expect(response.body.token).toBe(mockNewToken);

            // Check that the tokens were set as HTTP-only cookies
            const setCookieHeaders = response.headers['set-cookie'];

            // Check that the set-cookie header contains the expected attributes
            expect(setCookieHeaders).toEqual(
                expect.arrayContaining([
                    expect.stringContaining(`token=${mockNewToken}`),
                    expect.stringContaining('HttpOnly'),
                    expect.stringContaining('Max-Age=3600'),
                    expect.stringContaining('Path=/'),
                    expect.stringContaining('Expires=')
                ])
            );

            expect(logger.info).toHaveBeenCalledWith('Token refreshed successfully', { userId: validUser.id });
        });
    });

    describe('GET /auth/verify-email', () => {
        beforeEach(() => {
            jest.clearAllMocks();
        });

        it('should verify email successfully if a valid token is provided', async () => {
            const validToken = 'validVerificationToken';
            const mockUser = { id: 'user123' };

            // Mock database queries
            db.query
                .mockImplementationOnce((query, params) => {
                    if (query.includes('SELECT')) {
                        return { rows: [mockUser] }; // Simulate a user with the valid token
                    }
                    return { rows: [] };
                })
                .mockImplementationOnce((query, params) => {
                    if (query.includes('UPDATE')) {
                        return { rows: [] }; // Simulate successful update
                    }
                    return { rows: [] };
                });

            const response = await request(app)
                .get('/auth/verify-email')
                .query({ token: validToken })
                .send();

            expect(response.status).toBe(200);
            expect(response.body.message).toBe('Email verified successfully');
            expect(logger.info).toHaveBeenCalledWith('Email verified successfully', { userId: mockUser.id });
        });

        it('should return 400 if the verification token is invalid or expired', async () => {
            const invalidToken = 'invalidVerificationToken';

            // Mock database query to return no user
            db.query.mockImplementationOnce((query, params) => {
                return { rows: [] }; // Simulate no user found
            });

            const response = await request(app)
                .get('/auth/verify-email')
                .query({ token: invalidToken })
                .send();

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('Invalid or expired verification token');
            expect(logger.warn).toHaveBeenCalledWith('Invalid or expired verification token', { token: invalidToken });
        });

        it('should return 500 if there is a database error', async () => {
            const validToken = 'validVerificationToken';

            // Mock database query to throw an error
            db.query.mockImplementationOnce(() => {
                throw new Error('Database error');
            });

            const response = await request(app)
                .get('/auth/verify-email')
                .query({ token: validToken })
                .send();

            expect(response.status).toBe(500);
            expect(response.body.error).toBe('Internal server error');
            expect(logger.error).toHaveBeenCalledWith('Error during email verification', { error: 'Database error', token: validToken });
        });
    });
});
