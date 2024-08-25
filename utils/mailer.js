const nodemailer = require('nodemailer');

// Create a transport object using the SMTP transport
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: false, // true for 465, false for other ports
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// Function to send email
async function sendEmail(to, subject, text) {
    try {
        await transporter.sendMail({
            from: '"Your App" <test@mymail.com>',
            to: to,
            subject: subject,
            text: text,
        });
        console.log('Email sent successfully');
    } catch (error) {
        console.error('Error sending email:', error);
    }
}

module.exports = {
    sendEmail,
};
