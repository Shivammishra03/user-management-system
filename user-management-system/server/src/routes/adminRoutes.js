import express from 'express'
import { 
  adminLogin,
  getUsers,
  updateUser,
  deleteUser,
  getAuditLogs,
  getConfig,
  updateConfig
} from '../controllers/adminController.js'
import { adminAuth } from '../middleware/auth.js'
import { loginRateLimiter, adminRateLimiter } from '../middleware/rateLimit.js'

const router = express.Router()

router.post('/login', loginRateLimiter, adminLogin)
router.get('/users', adminAuth, adminRateLimiter, getUsers)
router.put('/users', adminAuth, adminRateLimiter, updateUser)
router.delete('/users', adminAuth, adminRateLimiter, deleteUser)
router.get('/audit-logs', adminAuth, adminRateLimiter, getAuditLogs)
router.get('/config', adminAuth, adminRateLimiter, getConfig)
router.put('/config', adminAuth, adminRateLimiter, updateConfig)

export default router