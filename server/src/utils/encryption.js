import CryptoJS from 'crypto-js'
import dotenv from 'dotenv'

dotenv.config()

let currentKey = process.env.ENCRYPTION_KEY

export const encryptData = (data) => {
  return CryptoJS.AES.encrypt(
    JSON.stringify(data),
    currentKey
  ).toString()
}

export const decryptData = (encryptedData) => {
  const bytes = CryptoJS.AES.decrypt(encryptedData, currentKey)
  return JSON.parse(bytes.toString(CryptoJS.enc.Utf8))
}

// Key rotation function (to be called periodically)
export const rotateKey = (newKey) => {
  currentKey = newKey
}