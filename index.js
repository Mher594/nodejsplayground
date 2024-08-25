const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;
const cookieParser = require('cookie-parser');
const logger = require('./logger');

app.use(express.json());
app.use(cookieParser()); // Use cookie parser middleware

const authRouter = require('./routes/auth');
const protectedRouter = require('./routes/protectedRoutes'); // Import your protected routes

app.use('/auth', authRouter);
app.use('/api', protectedRouter); // Apply protected routes

app.listen(PORT, () => {
    logger.info(`Server is running on port ${PORT}`);
});
