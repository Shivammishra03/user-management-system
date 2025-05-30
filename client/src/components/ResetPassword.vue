
```

## src/components/ResetPassword.vue
```vue
<template>
  <div class="card">
    <h2 class="text-2xl font-bold text-gray-800 mb-6">Reset Password</h2>
    <form @submit.prevent="resetPassword" class="space-y-4">
      <div>
        <label for="newPassword" class="block text-sm font-medium text-gray-700">New Password</label>
        <input
          id="newPassword"
          v-model="newPassword"
          type="password"
          required
          class="form-input"
          aria-required="true"
        />
        <p v-if="passwordError" class="error">{{ passwordError }}</p>
      </div>
      <button type="submit" class="form-button">Reset Password</button>
    </form>
  </div>
</template>

<script>
import axios from 'axios'
import CryptoJS from 'crypto-js'

export default {
  data() {
    return {
      newPassword: '',
      passwordError: ''
    }
  },
  methods: {
    validatePassword(password) {
      const minLength = 12
      const hasUpperCase = /[A-Z]/.test(password)
      const hasLowerCase = /[a-z]/.test(password)
      const hasNumbers = /\d/.test(password)
      const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password)

      if (password.length < minLength) {
        return 'Password must be at least 12 characters long'
      }
      if (!hasUpperCase || !hasLowerCase || !hasNumbers || !hasSpecialChar) {
        return 'Password must contain uppercase, lowercase, numbers, and special characters'
      }
      return ''
    },
    async resetPassword() {
      this.passwordError = this.validatePassword(this.newPassword)
      if (this.passwordError) return

      try {
        const email = localStorage.getItem('resetEmail')
        const encryptedData = CryptoJS.AES.encrypt(
          JSON.stringify({ email, newPassword: this.newPassword }),
          'your-encryption-key'
        ).toString()
        
        await axios.post('/api/reset-password', { 
          encryptedData,
          csrfToken: this.cookies.get('csrf_token')
        }, {
          headers: {
            Authorization: `Bearer ${localStorage.getItem('otpToken')}`
          }
        })
        
        localStorage.removeItem('resetEmail')
        localStorage.removeItem('otpToken')
        alert('Password reset successful')
        this.$router.push('/login')
      } catch (error) {
        console.error('Password reset failed:', error)
        this.$router.push('/forgot-password')
      }
    }
  }
}
</script>