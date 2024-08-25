const winston = require('winston');
const path = require('path');

// Define log file path with a unique filename
const logDir = path.join(__dirname, 'logs');

// Create the logs directory if it does not exist
const fs = require('fs');
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir);
}

// Create a unique filename based on the current timestamp
const timestamp = new Date().toISOString().replace(/:/g, '-'); // Replace colons to make the filename valid
const filename = `application-${timestamp}.log`;

// Create a new File transport instance with a unique filename
const fileTransport = new winston.transports.File({
    filename: path.join(logDir, filename),
});

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ level, message, timestamp, ...meta }) => {
            return `${timestamp} [${level}]: ${message} ${Object.keys(meta).length ? JSON.stringify(meta) : ''}`;
        })
    ),
    transports: [
        fileTransport,
        new winston.transports.Console()
    ],
});

module.exports = logger;
