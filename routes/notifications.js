/* User-facing notifications from admin broadcasts */

const express = require('express');
const router = express.Router();
const { authenticate } = require('../middleware/auth');
const db = require('../db/database');

router.get('/', authenticate, (req, res) => {
  try {
    const items = db.broadcasts.listForUser(req.user.email);
    res.json({
      notifications: items.map((n) => ({
        id: n.id,
        subject: n.subject,
        message: n.message,
        createdAt: n.created_at,
      })),
    });
  } catch (err) {
    console.error('GET /api/notifications error:', err);
    res.status(500).json({ error: 'Failed to load notifications' });
  }
});

module.exports = router;
