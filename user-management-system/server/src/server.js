import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import userRoutes from './routes/userRoutes.js'
import adminRoutes from './routes/adminRoutes.js'
import csrfRoutes from './routes/csrfRoutes.js'
// import pool from './config/db.js'
// import { csrfRoutes } from './routes/csrfRoutes.js'
// const express = require('express')
import dotenv from 'dotenv'
// import logger from './utils/logger.js'
import cookieParser from 'cookie-parser'
import { csrfMiddleware } from './middleware/csrf.js'

dotenv.config();
// Test database connection on startup

const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"]
    }
  }
}))
app.use(cors({
  origin: 'http://localhost:5173',
  credentials: true
}))
app.use(express.json())
app.use(cookieParser())
app.use(csrfMiddleware)
app.use('/api', userRoutes)
app.use('/api', csrfRoutes)
app.use('/api/admin', adminRoutes)

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})