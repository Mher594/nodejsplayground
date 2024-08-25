require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

pool.on('error', (err) => {
    console.error('Unexpected error on idle client', err);
    process.exit(-1);
});

module.exports = {
    query: async (text, params) => {
        try {
            const res = await pool.query(text, params);
            return res;
        } catch (err) {
            console.error('Database query error:', err);
            throw err;
        }
    },
};
