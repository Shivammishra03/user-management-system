// middleware/csrf.js
export const csrfMiddleware = (req, res, next) => {
    // Skip GETs (don't generate token here)
    if (req.method === 'GET') {
      return next()
    }
  
    const submittedToken = req.body.csrfToken || req.headers['x-csrf-token']
    const storedToken = req.cookies.csrf_token
  
    if (!submittedToken || !storedToken || submittedToken !== storedToken) {
      return res.status(403).json({ error: 'Invalid CSRF token' })
    }
  
    next()
  }
  