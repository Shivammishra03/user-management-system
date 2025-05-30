import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import CryptoJS from 'crypto-js'
import pool from '../config/db.js'
import { sendOtpEmail } from '../utils/mailer.js'
import logger from '../utils/logger.js'
import { sanitizeInput, validateEmail, validateName } from '../utils/validator.js'
import speakeasy from 'speakeasy'
import qrcode from 'qrcode'

export const register = async (req, res) => {
    try {
      // 🔐 CSRF Token Validation (Double Submit)
      const submittedToken = req.body.csrfToken || req.headers['x-csrf-token']
      const storedToken = req.cookies?.csrf_token
  
      if (!submittedToken || !storedToken || submittedToken !== storedToken) {
        return res.status(403).json({ error: 'Invalid CSRF token' })
      }
  
      // 🔓 Decrypt and parse user data
      const { encryptedData } = req.body
      const decryptedData = CryptoJS.AES.decrypt(
        encryptedData,
        process.env.ENCRYPTION_KEY
      ).toString(CryptoJS.enc.Utf8)
  
      let { email, password, name } = JSON.parse(decryptedData)
  
      // 🧼 Sanitize and validate input
      email = sanitizeInput(email)
      name = sanitizeInput(name)
  
      if (!validateEmail(email)) {
        return res.status(400).json({ error: 'Invalid email format' })
      }
  
      if (!validateName(name)) {
        return res.status(400).json({ error: 'Invalid name format' })
      }
  
      const [existingUsers] = await pool.query(
        'SELECT * FROM users WHERE email = ?', [email]
      )
  
      if (existingUsers.length > 0) {
        logger.warn(`Registration attempt for existing user: ${email}`)
        return res.status(400).json({ error: 'User already exists' })
      }
  
      // 🔐 Hash password and generate TOTP secret
      const hashedPassword = await bcrypt.hash(password, 12)
      const secret = speakeasy.generateSecret({ name: `GovernmentApp:${email}` })
  
      // 💾 Save new user
      await pool.query(
        'INSERT INTO users (email, password, name, totp_secret, role) VALUES (?, ?, ?, ?, ?)',
        [email, hashedPassword, name, secret.base32, 'admin']
      )
  
      logger.info(`New user registered: ${email}`)
  
      // 🪙 Generate auth token
      const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' })
  
      res.json({ token })
    } catch (error) {
      logger.error(`Registration error: ${error.message}`)
      res.status(500).json({ error: 'Server error' })
    }
  }

export const login = async (req, res) => {
  try {
    const { encryptedData } = req.body
    const decryptedData = CryptoJS.AES.decrypt(
      encryptedData,
      process.env.ENCRYPTION_KEY
    ).toString(CryptoJS.enc.Utf8)
    let { email, password, totpCode } = JSON.parse(decryptedData)

    email = sanitizeInput(email)

    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email])
    if (users.length === 0) {
      logger.warn(`Login attempt for non-existent user: ${email}`)
      return res.status(401).json({ error: 'Invalid credentials' })
    }

    const user = users[0]
    const validPassword = await bcrypt.compare(password, user.password)
    if (!validPassword) {
      logger.warn(`Invalid password attempt for user: ${email}`)
      return res.status(401).json({ error: 'Invalid credentials' })
    }

    const validTotp = speakeasy.totp.verify({
      secret: user.totp_secret,
      encoding: 'base32',
      token: totpCode
    })

    if (!validTotp) {
      logger.warn(`Invalid 2FA code for user: ${email}`)
      return res.status(401).json({ error: 'Invalid 2FA code' })
    }

    logger.info(`Successful login for user: ${email}`)
    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' })
    res.cookie('session', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 3600000
    })
    res.json({ token })
  } catch (error) {
    logger.error(`Login error: ${error.message}`)
    res.status(500).json({ error: 'Server error' })
  }
}

export const getProfile = async (req, res) => {
  try {
    const [users] = await pool.query('SELECT email, name FROM users WHERE email = ?', [
      req.user.email
    ])
    
    const userData = {
      email: users[0].email,
      name: users[0].name
    }
    
    const encryptedData = CryptoJS.AES.encrypt(
      JSON.stringify(userData),
      process.env.ENCRYPTION_KEY
    ).toString()
    
    logger.info(`Profile accessed for user: ${req.user.email}`)
    res.json({ encryptedData })
  } catch (error) {
    logger.error(`Profile access error: ${error.message}`)
    res.status(500).json({ error: 'Server error' })
  }
}

export const forgotPassword = async (req, res) => {
  try {
    const { encryptedData } = req.body
    const email = CryptoJS.AES.decrypt(
      encryptedData,
      process.env.ENCRYPTION_KEY
    ).toString(CryptoJS.enc.Utf8)

    const sanitizedEmail = sanitizeInput(email)
    if (!validateEmail(sanitizedEmail)) {
      return res.status(400).json({ error: 'Invalid email format' })
    }

    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [sanitizedEmail])
    if (users.length === 0) {
      logger.warn(`Password reset attempt for non-existent user: ${sanitizedEmail}`)
      return res.status(404).json({ error: 'User not found' })
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString()
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000)

    await pool.query(
      'INSERT INTO otps (email, otp, expires_at) VALUES (?, ?, ?)',
      [sanitizedEmail, otp, expiresAt]
    )

    await sendOtpEmail(sanitizedEmail, otp)
    logger.info(`OTP sent for password reset: ${sanitizedEmail}`)
    res.json({ message: 'OTP sent' })
  } catch (error) {
    logger.error(`Forgot password error: ${error.message}`)
    res.status(500).json({ error: 'Server error' })
  }
}

export const verifyOtp = async (req, res) => {
  try {
    const { encryptedData } = req.body
    const decryptedData = CryptoJS.AES.decrypt(
      encryptedData,
      process.env.ENCRYPTION_KEY
    ).toString(CryptoJS.enc.Utf8)
    let { email, otp } = JSON.parse(decryptedData)

    email = sanitizeInput(email)
    otp = sanitizeInput(otp)

    const [otps] = await pool.query(
      'SELECT * FROM otps WHERE email = ? AND otp = ? AND expires_at > NOW()',
      [email, otp]
    )

    if (otps.length === 0) {
      logger.warn(`Invalid OTP attempt for user: ${email}`)
      return res.status(400).json({ error: 'Invalid or expired OTP' })
    }

    const otpToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '15m' })
    await pool.query('DELETE FROM otps WHERE email = ?', [email])
    
    logger.info(`OTP verified for user: ${email}`)
    res.json({ otpToken })
  } catch (error) {
    logger.error(`OTP verification error: ${error.message}`)
    res.status(500).json({ error: 'Server error' })
  }
}

export const resetPassword = async (req, res) => {
  try {
    const { encryptedData } = req.body
    const decryptedData = CryptoJS.AES.decrypt(
      encryptedData,
      process.env.ENCRYPTION_KEY
    ).toString(CryptoJS.enc.Utf8)
    let { email, newPassword } = JSON.parse(decryptedData)

    email = sanitizeInput(email)

    if (email !== req.user.email) {
      logger.warn(`Unauthorized password reset attempt for user: ${email}`)
      return res.status(403).json({ error: 'Unauthorized' })
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12)
    await pool.query(
      'UPDATE users SET password = ? WHERE email = ?',
      [hashedPassword, email]
    )

    logger.info(`Password reset successful for user: ${email}`)
    res.json({ message: 'Password reset successful' })
  } catch (error) {
    logger.error(`Password reset error: ${error.message}`)
    res.status(500).json({ error: 'Server error' })
  }
}

export const changePassword = async (req, res) => {
  try {
    const { encryptedData } = req.body
    const decryptedData = CryptoJS.AES.decrypt(
      encryptedData,
      process.env.ENCRYPTION_KEY
    ).toString(CryptoJS.enc.Utf8)
    let { currentPassword, newPassword } = JSON.parse(decryptedData)

    const [users] = await pool.query(
      'SELECT password FROM users WHERE email = ?',
      [req.user.email]
    )

    const validPassword = await bcrypt.compare(currentPassword, users[0].password)
    if (!validPassword) {
      logger.warn(`Invalid password change attempt for user: ${req.user.email}`)
      return res.status(401).json({ error: 'Invalid current password' })
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12)
    await pool.query(
      'UPDATE users SET password = ? WHERE email = ?',
      [hashedPassword, req.user.email]
    )

    logger.info(`Password changed for user: ${req.user.email}`)
    res.json({ message: 'Password changed successfully' })
  } catch (error) {
    logger.error(`Password change error: ${error.message}`)
    res.status(500).json({ error: 'Server error' })
  }
}

export const twoFactorSetup = async (req, res) => {
  try {
    const [users] = await pool.query(
      'SELECT totp_secret FROM users WHERE email = ?',
      [req.user.email]
    )
    
    const secret = users[0].totp_secret
    const qrCodeUrl = await qrcode.toDataURL(
      `otpauth://totp/GovernmentApp:${req.user.email}?secret=${secret}&issuer=GovernmentApp`
    )

    logger.info(`2FA setup accessed for user: ${req.user.email}`)
    res.json({ qrCode: qrCodeUrl })
  } catch (error) {
    logger.error(`2FA setup error: ${error.message}`)
    res.status(500).json({ error: 'Server error' })
  }
}

export const verifyTotp = async (req, res) => {
  try {
    const { encryptedData } = req.body
    const totpCode = CryptoJS.AES.decrypt(
      encryptedData,
      process.env.ENCRYPTION_KEY
    ).toString(CryptoJS.enc.Utf8)

    const [users] = await pool.query(
      'SELECT totp_secret FROM users WHERE email = ?',
      [req.user.email]
    )

    const validTotp = speakeasy.totp.verify({
      secret: users[0].totp_secret,
      encoding: 'base32',
      token: totpCode
    })

    if (!validTotp) {
      logger.warn(`Invalid 2FA verification attempt for user: ${req.user.email}`)
      return res.status(401).json({ error: 'Invalid 2FA code' })
    }

    logger.info(`2FA verified for user: ${req.user.email}`)
    res.json({ message: '2FA verified successfully' })
  } catch (error) {
    logger.error(`2FA verification error: ${error.message}`)
    res.status(500).json({ error: 'Server error' })
  }
}