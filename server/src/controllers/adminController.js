import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import CryptoJS from 'crypto-js'
import pool from '../config/db.js'
import logger from '../utils/logger.js'
import { sanitizeInput, validateEmail } from '../utils/validator.js'
import speakeasy from 'speakeasy'

export const adminLogin = async (req, res) => {
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
      logger.warn(`Admin login attempt for non-existent user: ${email}`)
      return res.status(401).json({ error: 'Invalid credentials' })
    }

    const user = users[0]
    if (user.role !== 'admin') {
      logger.warn(`Non-admin login attempt for admin panel: ${email}`)
      return res.status(403).json({ error: 'Admin access required' })
    }

    const validPassword = await bcrypt.compare(password, user.password)
    if (!validPassword) {
      logger.warn(`Invalid password attempt for admin: ${email}`)
      return res.status(401).json({ error: 'Invalid credentials' })
    }

    const validTotp = speakeasy.totp.verify({
      secret: user.totp_secret,
      encoding: 'base32',
      token: totpCode
    })

    if (!validTotp) {
      logger.warn(`Invalid 2FA code for admin: ${email}`)
      return res.status(401).json({ error: 'Invalid 2FA code' })
    }

    logger.info(`Successful admin login: ${email}`)
    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' })
    res.cookie('session', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 3600000
    })
    res.json({ token })
  } catch (error) {
    logger.error(`Admin login error: ${error.message}`)
    res.status(500).json({ error: 'Server error' })
  }
}

export const getUsers = async (req, res) => {
  try {
    const [users] = await pool.query('SELECT id, email, name, role FROM users')
    
    const encryptedData = CryptoJS.AES.encrypt(
      JSON.stringify(users),
      process.env.ENCRYPTION_KEY
    ).toString()
    
    logger.info(`User list accessed by admin: ${req.user.email}`)
    res.json({ encryptedData })
  } catch (error) {
    logger.error(`User list access error: ${error.message}`)
    res.status(500).json({ error: 'Server error' })
  }
}

export const updateUser = async (req, res) => {
  try {
    const { encryptedData } = req.body
    const decryptedData = CryptoJS.AES.decrypt(
      encryptedData,
      process.env.ENCRYPTION_KEY
    ).toString(CryptoJS.enc.Utf8)
    let { id, name, role } = JSON.parse(decryptedData)

    name = sanitizeInput(name)
    role = sanitizeInput(role)

    if (!['user', 'admin'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role' })
    }

    await pool.query(
      'UPDATE users SET name = ?, role = ? WHERE id = ?',
      [name, role, id]
    )

    logger.info(`User updated by admin: ${req.user.email}, userId: ${id}`)
    await pool.query(
      'INSERT INTO audit_logs (user_email, action, details) VALUES (?, ?, ?)',
      [req.user.email, 'update_user', `Updated user ${id}: name=${name}, role=${role}`]
    )

    res.json({ message: 'User updated successfully' })
  } catch (error) {
    logger.error(`User update error: ${error.message}`)
    res.status(500).json({ error: 'Server error' })
  }
}

export const deleteUser = async (req, res) => {
  try {
    const { encryptedData } = req.body
    const decryptedData = CryptoJS.AES.decrypt(
      encryptedData,
      process.env.ENCRYPTION_KEY
    ).toString(CryptoJS.enc.Utf8)
    const { id } = JSON.parse(decryptedData)

    const [users] = await pool.query('SELECT email FROM users WHERE id = ?', [id])
    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' })
    }

    await pool.query('DELETE FROM users WHERE id = ?', [id])
    
    logger.info(`User deleted by admin: ${req.user.email}, userId: ${id}`)
    await pool.query(
      'INSERT INTO audit_logs (user_email, action, details) VALUES (?, ?, ?)',
      [req.user.email, 'delete_user', `Deleted user ${id}`]
    )

    res.json({ message: 'User deleted successfully' })
  } catch (error) {
    logger.error(`User delete error: ${error.message}`)
    res.status(500).json({ error: 'Server error' })
  }
}

export const getAuditLogs = async (req, res) => {
  try {
    const [logs] = await pool.query('SELECT * FROM audit_logs ORDER BY created_at DESC')
    
    const encryptedData = CryptoJS.AES.encrypt(
      JSON.stringify(logs),
      process.env.ENCRYPTION_KEY
    ).toString()
    
    logger.info(`Audit logs accessed by admin: ${req.user.email}`)
    res.json({ encryptedData })
  } catch (error) {
    logger.error(`Audit logs access error: ${error.message}`)
    res.status(500).json({ error: 'Server error' })
  }
}

export const getConfig = async (req, res) => {
  try {
    // In a real system, this would come from a database or config file
    const config = {
      sessionTimeout: 60,
      maxLoginAttempts: 5
    }
    
    const encryptedData = CryptoJS.AES.encrypt(
      JSON.stringify(config),
      process.env.ENCRYPTION_KEY
    ).toString()
    
    logger.info(`Config accessed by admin: ${req.user.email}`)
    res.json({ encryptedData })
  } catch (error) {
    logger.error(`Config access error: ${error.message}`)
    res.status(500).json({ error: 'Server error' })
  }
}

export const updateConfig = async (req, res) => {
  try {
    const { encryptedData } = req.body
    const decryptedData = CryptoJS.AES.decrypt(
      encryptedData,
      process.env.ENCRYPTION_KEY
    ).toString(CryptoJS.enc.Utf8)
    const config = JSON.parse(decryptedData)

    // In a real system, this would update a database or config file
    logger.info(`Config updated by admin: ${req.user.email}, config: ${JSON.stringify(config)}`)
    await pool.query(
      'INSERT INTO audit_logs (user_email, action, details) VALUES (?, ?, ?)',
      [req.user.email, 'update_config', `Updated config: ${JSON.stringify(config)}`]
    )

    res.json({ message: 'Configuration updated successfully' })
  } catch (error) {
    logger.error(`Config update error: ${error.message}`)
    res.status(500).json({ error: 'Server error' })
  }
}