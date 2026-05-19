const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const pool = require('../db');
const authMiddleware = require('../middleware/auth');
require('dotenv').config();

// Helper: hash Aadhaar with SHA-256
function hashAadhar(aadhar) {
  return crypto.createHash('sha256').update(aadhar).digest('hex');
}

// GET /student/profile
// Returns student details (masked Aadhaar, bank details etc.)
// Requires JWT from verify-otp step
router.get('/profile', authMiddleware, async (req, res) => {
  const { studentCode } = req.student;

  try {
    const result = await pool.query(
      'SELECT * FROM students WHERE student_code = $1',
      [studentCode]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Student not found' });
    }

    const s = result.rows[0];

    // Mask Aadhaar — only send last 4 digits
    const maskedAadhar = `XXXX XXXX ${s.aadhar_last4}`;

    res.json({
      studentCode: s.student_code,
      name: s.name,
      dob: s.dob,
      schoolName: s.school_name,
      className: s.class_name,
      section: s.section,
      roll: s.roll_number,
      maskedAadhar,
      bankName: s.bank_name,
      branchName: s.branch_name,
      ifsc: s.ifsc,
      accountNumber: s.account_number,
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /student/verify-aadhar
// Flutter sends raw 12-digit Aadhaar → backend hashes → compares → sends OTP
router.post('/verify-aadhar', authMiddleware, async (req, res) => {
  const { studentCode } = req.student;
  const { aadhar } = req.body;

  if (!aadhar || aadhar.length !== 12) {
    return res.status(400).json({ message: 'Valid 12-digit Aadhaar is required' });
  }

  try {
    const result = await pool.query(
      'SELECT aadhar_hash, parent_phone FROM students WHERE student_code = $1',
      [studentCode]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Student not found' });
    }

    const { aadhar_hash, parent_phone } = result.rows[0];
    const incomingHash = hashAadhar(aadhar);

    if (incomingHash !== aadhar_hash) {
      return res.status(401).json({ message: 'Aadhaar does not match our records' });
    }

    // Aadhaar matched — generate and store confirmation OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await pool.query(
      'UPDATE otps SET used = true WHERE student_code = $1',
      [studentCode]
    );
    await pool.query(
      'INSERT INTO otps (student_code, otp_code, expires_at, used) VALUES ($1, $2, $3, false)',
      [studentCode, otp, expiresAt]
    );

    // TODO: send real SMS via NIC API
    console.log(`Confirmation OTP for ${studentCode}: ${otp} → ${parent_phone}`);

    res.json({
      message: 'Aadhaar verified. OTP sent.',
      debug_otp: otp  // remove in production
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /student/submit
// Final step — verify confirmation OTP and save declaration
router.post('/submit', authMiddleware, async (req, res) => {
  const { studentCode } = req.student;
  const { otp } = req.body;

  if (!otp) {
    return res.status(400).json({ message: 'OTP is required' });
  }

  try {
    const otpResult = await pool.query(
      `SELECT * FROM otps 
       WHERE student_code = $1 
       AND otp_code = $2 
       AND used = false 
       AND expires_at > NOW()
       ORDER BY created_at DESC LIMIT 1`,
      [studentCode, otp]
    );

    if (otpResult.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid or expired OTP' });
    }

    await pool.query('UPDATE otps SET used = true WHERE id = $1', [otpResult.rows[0].id]);

    // Save declaration
    const appNumber = `WB-${new Date().getFullYear()}-${Date.now() % 100000}`;
    await pool.query(
      `INSERT INTO declarations (student_code, application_number, submitted_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (student_code) DO UPDATE SET submitted_at = NOW(), application_number = $2`,
      [studentCode, appNumber]
    );

    res.status(201).json({
      message: 'Declaration submitted successfully',
      applicationNumber: appNumber,
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;