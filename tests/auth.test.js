const request = require('supertest');
const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const authRouter = require('../routes/auth'); // Adjust the path to your routes file

app.use(bodyParser.json());
app.use('/auth', authRouter);

describe('Auth Routes', () => {
    // Test sign-up route
    describe('POST /auth/signup', () => {
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
    });

    // Test sign-in route
    describe('POST /auth/signin', () => {

        it('should return error for invalid email format during sign-in', async () => {
            const response = await request(app)
                .post('/auth/signin')
                .send({
                    email: 'invalid-email',
                    password: 'Test1234'
                });

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('Invalid email format');
        });
    });
});
