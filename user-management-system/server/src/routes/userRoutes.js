import express from 'express'
import { 
  register, 
  login, 
  getProfile, 
  forgotPassword, 
  verifyOtp,
  resetPassword, 
  changePassword,
  twoFactorSetup,
  verifyTotp
} from '../controllers/userController.js'
import { auth } from '../middleware/auth.js'
import { loginRateLimiter, apiRateLimiter } from '../middleware/rateLimit.js'

const router = express.Router()

router.post('/register', apiRateLimiter, register)
router.post('/login', loginRateLimiter, login)
router.get('/profile', auth, getProfile)
router.post('/forgot-password', apiRateLimiter, forgotPassword)
router.post('/verify-otp', apiRateLimiter, verifyOtp)
router.post('/reset-password', auth, apiRateLimiter, resetPassword)
router.post('/change-password', auth, apiRateLimiter, changePassword)
router.get('/two-factor-setup', auth, twoFactorSetup)
router.post('/verify-totp', auth, verifyTotp)

export default router