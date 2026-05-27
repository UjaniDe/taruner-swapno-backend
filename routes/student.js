const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const pool = require('../db');
const authMiddleware = require('../middleware/auth');
require('dotenv').config();

function hashAadhar(aadhar) {
  return crypto.createHash('sha256').update(aadhar).digest('hex');
}

// GET /student/profile
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

    // HARDCODED for development - replace with real SMS via NIC API later
    const otp = '123456';
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await pool.query(
      'UPDATE otps SET used = true WHERE student_code = $1',
      [studentCode]
    );
    await pool.query(
      'INSERT INTO otps (student_code, otp_code, expires_at, used) VALUES ($1, $2, $3, false)',
      [studentCode, otp, expiresAt]
    );

    console.log(`Confirmation OTP for ${studentCode}: ${otp} → ${parent_phone}`);

    res.json({ message: 'Aadhaar verified. OTP sent.' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /student/submit
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

// POST /student/find-account
// Matches student code + mobile + aadhaar against DB
router.post('/find-account', async (req, res) => {
  const { studentCode, mobile, aadhar } = req.body;

  if (!studentCode || !mobile || !aadhar) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  if (aadhar.length !== 12) {
    return res.status(400).json({ message: 'Invalid Aadhaar number' });
  }

  try {
    const result = await pool.query(
      'SELECT * FROM students WHERE student_code = $1',
      [studentCode]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Student not found' });
    }

    const student = result.rows[0];
    const incomingHash = hashAadhar(aadhar);

    if (
      student.aadhar_hash !== incomingHash ||
      student.parent_phone !== mobile
    ) {
      return res.status(401).json({ message: 'Details do not match our records' });
    }

    res.json({ message: 'Student found', studentCode });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /student/verify-and-send-otp
// Verifies aadhaar hash + mobile, sends OTP to that number
router.post('/verify-and-send-otp', async (req, res) => {
  const { studentCode, aadhar, mobile } = req.body;

  if (!studentCode || !aadhar || !mobile) {
    return res.status(400).json({ message: 'All fields are required' });
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

    if (incomingHash !== aadhar_hash || parent_phone !== mobile) {
      return res.status(401).json({ message: 'Details do not match our records' });
    }

    // HARDCODED for development - replace with real SMS via NIC API later
    const otp = '123456';
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await pool.query(
      'UPDATE otps SET used = true WHERE student_code = $1',
      [studentCode]
    );
    await pool.query(
      'INSERT INTO otps (student_code, otp_code, expires_at, used) VALUES ($1, $2, $3, false)',
      [studentCode, otp, expiresAt]
    );

    console.log(`Reject flow OTP for ${studentCode}: ${otp} → ${mobile}`);

    res.json({ message: 'OTP sent successfully' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /student/reject
// Saves rejection remark to DB
router.post('/reject', authMiddleware, async (req, res) => {
  const { studentCode } = req.student;
  const { remarks } = req.body;

  if (!remarks || remarks.trim() === '') {
    return res.status(400).json({ message: 'Remarks are required' });
  }

  try {
    await pool.query(
      `INSERT INTO rejections (student_code, remarks)
       VALUES ($1, $2)`,
      [studentCode, remarks.trim()]
    );

    res.status(201).json({ message: 'Rejection submitted successfully' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});
module.exports = router;