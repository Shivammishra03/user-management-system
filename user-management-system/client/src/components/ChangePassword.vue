<template>
    <div class="card">
      <h2 class="text-2xl font-bold text-gray-800 mb-6">Change Password</h2>
      <form @submit.prevent="changePassword" class="space-y-4">
        <div>
          <label for="currentPassword" class="block text-sm font-medium text-gray-700">Current Password</label>
          <input
            id="currentPassword"
            v-model="form.currentPassword"
            type="password"
            required
            class="form-input"
            aria-required="true"
          />
        </div>
        <div>
          <label for="newPassword" class="block text-sm font-medium text-gray-700">New Password</label>
          <input
            id="newPassword"
            v-model="form.newPassword"
            type="password"
            required
            class="form-input"
            aria-required="true"
          />
          <p v-if="passwordError" class="error">{{ passwordError }}</p>
        </div>
        <button type="submit" class="form-button">Change Password</button>
      </form>
    </div>
  </template>
  
  <script>
  import axios from 'axios'
  import CryptoJS from 'crypto-js'
  
  export default {
    data() {
      return {
        form: {
          currentPassword: '',
          newPassword: ''
        },
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
      async changePassword() {
        this.passwordError = this.validatePassword(this.form.newPassword)
        if (this.passwordError) return
  
        try {
          const encryptedData = CryptoJS.AES.encrypt(
            JSON.stringify(this.form),
            'your-encryption-key'
          ).toString()
          
          await axios.post('/api/change-password', { 
            encryptedData,
            csrfToken: this.cookies.get('csrf_token')
          }, {
            headers: {
              Authorization: `Bearer ${localStorage.getItem('token')}`
            }
          })
          alert('Password changed successfully')
          this.$router.push('/profile')
        } catch (error) {
          console.error('Password change failed:', error)
        }
      }
    }
  }
  </script>