import xss from 'xss'

export const sanitizeInput = (input) => {
  if (typeof input === 'string') {
    return xss(input)
  }
  if (typeof input === 'object' && input !== null) {
    const sanitized = {}
    for (const key in input) {
      sanitized[key] = sanitizeInput(input[key])
    }
    return sanitized
  }
  return input
}

export const validateEmail = (email) => {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return re.test(email)
}

export const validateName = (name) => {
  const re = /^[a-zA-Z\s]{2,50}$/
  return re.test(name)
}