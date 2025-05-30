import express from 'express'
import crypto from 'crypto'

const router = express.Router()

router.get('/csrf-token', (req, res) => {
  const csrfToken = crypto.randomBytes(32).toString('hex')

  res.cookie('csrf_token', csrfToken, {
    httpOnly: false,
    secure: false, // true in production/HTTPS
    sameSite: 'Strict'
  })

  res.json({ message: 'CSRF token set' })
})

export default router
