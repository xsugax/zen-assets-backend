/* ════════════════════════════════════════════════════════════
   routes/kyc.js — KYC Identity Verification
   ZEN ASSETS Backend

   POST  /api/kyc/submit           — submit documents (base64)
   GET   /api/kyc/status           — get user's KYC status
   GET   /api/kyc/pending          — admin: list pending submissions
   PATCH /api/kyc/:id/review       — admin: approve or reject
════════════════════════════════════════════════════════════ */

const express = require('express');
const router  = express.Router();
const { v4: uuid } = require('uuid');
const { authenticate, requireAdmin } = require('../middleware/auth');
const db      = require('../db/database');
const email   = require('../services/email');

// ── POST /api/kyc/submit — upload KYC documents ────────────
router.post('/submit', authenticate, (req, res) => {
  try {
    const userId = req.user.id;
    const user   = db.users.findById(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (user.kyc_status === 'verified') {
      return res.status(400).json({ error: 'Your account is already verified' });
    }

    const { doc_type, doc_front, doc_back, selfie, full_name, date_of_birth, country } = req.body;

    if (!doc_type || !doc_front) {
      return res.status(400).json({ error: 'doc_type and doc_front (base64) are required' });
    }

    // Max size check: base64 ~4/3 of binary — 5MB limit = ~6.7MB base64
    const MAX_B64 = 7 * 1024 * 1024; // ~7MB
    if (doc_front.length > MAX_B64) return res.status(400).json({ error: 'Document too large (max 5MB)' });
    if (doc_back && doc_back.length > MAX_B64) return res.status(400).json({ error: 'Document (back) too large' });
    if (selfie  && selfie.length  > MAX_B64) return res.status(400).json({ error: 'Selfie too large (max 5MB)' });

    const rawDb = db.raw();

    // Invalidate any existing pending/rejected submission
    rawDb.prepare(`
      UPDATE kyc_documents SET status = 'superseded' WHERE user_id = ? AND status IN ('pending','rejected')
    `).run(userId);

    const id = uuid();
    rawDb.prepare(`
      INSERT INTO kyc_documents (
        id, user_id, doc_type, doc_front, doc_back, selfie,
        full_name, date_of_birth, country, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
    `).run(id, userId, doc_type, doc_front, doc_back || null, selfie || null,
           full_name || user.full_name, date_of_birth || null, country || user.country);

    // Update user kyc_status to submitted
    db.users.updateKYC(userId, 'submitted');

    db.audit.log(userId, 'kyc_submitted', { docType: doc_type }, 'info', req.ip);

    // Notify user their docs are under review
    email.sendKYCUpdate(user, 'submitted').catch(() => {});

    res.status(201).json({ id, message: 'KYC documents submitted. You will be notified once reviewed.' });
  } catch (err) {
    console.error('POST /api/kyc/submit error:', err);
    res.status(500).json({ error: 'Failed to submit KYC documents' });
  }
});

// ── GET /api/kyc/status — get current user's KYC status ────
router.get('/status', authenticate, (req, res) => {
  try {
    const user = db.users.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const rawDb = db.raw();
    const doc = rawDb.prepare(`
      SELECT id, doc_type, status, submitted_at, reviewed_at, reviewer_notes
      FROM kyc_documents
      WHERE user_id = ?
      ORDER BY submitted_at DESC
      LIMIT 1
    `).get(req.user.id);

    res.json({
      kyc_status: user.kyc_status,
      submission:  doc || null,
    });
  } catch (err) {
    console.error('GET /api/kyc/status error:', err);
    res.status(500).json({ error: 'Failed to fetch KYC status' });
  }
});

// ── GET /api/kyc/pending — admin: list pending submissions ─
router.get('/pending', authenticate, requireAdmin, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });

  try {
    const rawDb = db.raw();
    const pending = rawDb.prepare(`
      SELECT k.id, k.user_id, k.doc_type, k.full_name, k.date_of_birth,
             k.country, k.status, k.submitted_at,
             u.email, u.kyc_status
      FROM kyc_documents k
      JOIN users u ON u.id = k.user_id
      WHERE k.status = 'pending'
      ORDER BY k.submitted_at ASC
    `).all();

    res.json({ pending, count: pending.length });
  } catch (err) {
    console.error('GET /api/kyc/pending error:', err);
    res.status(500).json({ error: 'Failed to fetch pending KYC' });
  }
});

// ── GET /api/kyc/:id — admin: get document details with images
router.get('/:id', authenticate, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });

  try {
    const rawDb = db.raw();
    const doc = rawDb.prepare(`
      SELECT k.*, u.email, u.full_name as user_name
      FROM kyc_documents k
      JOIN users u ON u.id = k.user_id
      WHERE k.id = ?
    `).get(req.params.id);

    if (!doc) return res.status(404).json({ error: 'KYC submission not found' });

    res.json(doc);
  } catch (err) {
    console.error('GET /api/kyc/:id error:', err);
    res.status(500).json({ error: 'Failed to fetch KYC document' });
  }
});

// ── PATCH /api/kyc/:id/review — admin: approve or reject ───
router.patch('/:id/review', authenticate, requireAdmin, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });

  try {
    const { decision, notes } = req.body; // decision: 'approved' | 'rejected'
    if (!['approved', 'rejected'].includes(decision)) {
      return res.status(400).json({ error: 'decision must be approved or rejected' });
    }

    const rawDb = db.raw();
    const doc = rawDb.prepare('SELECT * FROM kyc_documents WHERE id = ?').get(req.params.id);
    if (!doc) return res.status(404).json({ error: 'KYC submission not found' });
    if (doc.status !== 'pending') return res.status(400).json({ error: 'Submission already reviewed' });

    // Update KYC document status
    rawDb.prepare(`
      UPDATE kyc_documents
      SET status = ?, reviewer_id = ?, reviewer_notes = ?, reviewed_at = datetime('now')
      WHERE id = ?
    `).run(decision, req.user.id, notes || null, doc.id);

    // Update user kyc_status
    const newUserStatus = decision === 'approved' ? 'verified' : 'rejected';
    db.users.updateKYC(doc.user_id, newUserStatus);

    const user = db.users.findById(doc.user_id);
    db.audit.log(req.user.id, `kyc_${decision}`, { kycDocId: doc.id, targetUser: doc.user_id, notes }, 'info', req.ip);

    // Notify user
    if (user) email.sendKYCUpdate(user, newUserStatus).catch(() => {});

    res.json({ message: `KYC ${decision}`, user_kyc_status: newUserStatus });
  } catch (err) {
    console.error('PATCH /api/kyc/:id/review error:', err);
    res.status(500).json({ error: 'Failed to review KYC' });
  }
});

module.exports = router;
