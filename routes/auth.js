const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const pool = require('../db');
require('dotenv').config();

// POST /auth/send-otp
router.post('/send-otp', async (req, res) => {
  const { studentCode } = req.body;

  if (!studentCode) {
    return res.status(400).json({ message: 'Student code is required' });
  }

  try {
    const result = await pool.query(
      'SELECT * FROM students WHERE student_code = $1',
      [studentCode]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Student not found' });
    }

    // HARDCODED OTP for development - replace with real SMS later
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

    res.json({ message: 'OTP sent successfully' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /auth/verify-otp
router.post('/verify-otp', async (req, res) => {
  const { studentCode, otp } = req.body;

  if (!studentCode || !otp) {
    return res.status(400).json({ message: 'Student code and OTP are required' });
  }

  try {
    const result = await pool.query(
      `SELECT * FROM otps 
       WHERE student_code = $1 
       AND otp_code = $2 
       AND used = false 
       AND expires_at > NOW()
       ORDER BY created_at DESC 
       LIMIT 1`,
      [studentCode, otp]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid or expired OTP' });
    }

    await pool.query(
      'UPDATE otps SET used = true WHERE id = $1',
      [result.rows[0].id]
    );

    const token = jwt.sign(
      { studentCode },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ message: 'OTP verified', token });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;