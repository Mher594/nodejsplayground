const { Pool } = require('pg');

// Load environment variables from a .env file if it exists
require('dotenv').config();

const pool = new Pool({
    user: process.env.DB_USER,           // Your PostgreSQL username
    host: process.env.DB_HOST,           // Your PostgreSQL host
    database: process.env.DB_NAME,       // Your PostgreSQL database name
    password: process.env.DB_PASSWORD,   // Your PostgreSQL password
    port: process.env.DB_PORT,           // Your PostgreSQL port (default is 5432)
});

let client;

beforeAll(async () => {
    try {
        client = await pool.connect();
    } catch (err) {
        console.error('Failed to connect to the database:', err);
        process.exit(1); // Exit the process if database connection fails
    }
});

beforeEach(async () => {
    try {
        await client.query('BEGIN');
    } catch (err) {
        console.error('Failed to begin transaction:', err);
        throw err; // Ensure the test fails if transaction setup fails
    }
});

afterEach(async () => {
    try {
        await client.query('ROLLBACK');
    } catch (err) {
        console.error('Failed to rollback transaction:', err);
        throw err; // Ensure the test fails if rollback fails
    }
});

afterAll(async () => {
    console.log('Starting cleanup...');
    try {
        if (client) {
            await client.release();
            console.log('Client released.');
        }
        await pool.end(); // Ensure that this is awaited properly
        console.log('Pool ended.');
    } catch (err) {
        console.error('Failed to close database connections:', err);
        process.exit(1); // Exit the process if teardown fails
    }
    console.log('Cleanup done.');
}, 10000); // Increase timeout if necessary
