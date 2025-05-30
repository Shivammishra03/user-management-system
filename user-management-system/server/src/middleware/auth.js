import jwt from 'jsonwebtoken'
import logger from '../utils/logger.js'

export const auth = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '') || req.cookies.session
  
  if (!token) {
    logger.warn('Access attempt without token')
    return res.status(401).json({ error: 'Access denied' })
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    req.user = decoded
    next()
  } catch (error) {
    logger.warn(`Invalid token attempt: ${error.message}`)
    res.status(401).json({ error: 'Invalid token' })
  }
}

export const adminAuth = async (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '') || req.cookies.session
  
  if (!token) {
    logger.warn('Admin access attempt without token')
    return res.status(401).json({ error: 'Access denied' })
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    const [users] = await pool.query('SELECT role FROM users WHERE email = ?', [decoded.email])
    
    if (users.length === 0 || users[0].role !== 'admin') {
      logger.warn(`Non-admin access attempt: ${decoded.email}`)
      return res.status(403).json({ error: 'Admin access required' })
    }
    
    req.user = decoded
    next()
  } catch (error) {
    logger.warn(`Invalid admin token attempt: ${error.message}`)
    res.status(401).json({ error: 'Invalid token' })
  }
}