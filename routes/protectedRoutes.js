const express = require('express');
const router = express.Router();
const authenticateToken = require('../middleware/authenticateToken');

// Example protected route
router.get('/profile', authenticateToken, (req, res) => {
    res.status(200).json({ message: 'This is a protected route', user: req.user });
});

module.exports = router;
