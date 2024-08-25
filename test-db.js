require('dotenv').config();
const { Pool } = require('pg');

// Create a new pool instance
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

// Test the connection
async function testConnection() {
    try {
        const client = await pool.connect();
        console.log('Connected to the database successfully!');

        // Perform a simple query
        const result = await client.query('SELECT NOW()');
        console.log('Current time from database:', result.rows[0].now);

        client.release();
    } catch (err) {
        console.error('Error connecting to the database:', err.stack);
    }
}

testConnection();