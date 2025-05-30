<template>
    <div class="card">
      <h2 class="text-2xl font-bold text-gray-800 mb-6">Forgot Password</h2>
      <form @submit.prevent="requestOtp" class="space-y-4">
        <div>
          <label for="email" class="block text-sm font-medium text-gray-700">Email</label>
          <input
            id="email"
            v-model="email"
            type="email"
            required
            class="form-input"
            aria-required="true"
          />
        </div>
        <button type="submit" class="form-button">Request OTP</button>
      </form>
    </div>
  </template>
  
  <script>
  import axios from 'axios'
  import CryptoJS from 'crypto-js'
  
  export default {
    data() {
      return {
        email: ''
      }
    },
    methods: {
      async requestOtp() {
        try {
          const encryptedData = CryptoJS.AES.encrypt(
            this.email,
            'your-encryption-key'
          ).toString()
          
          await axios.post('/api/forgot-password', { 
            encryptedData,
            csrfToken: this.cookies.get('csrf_token')
          })
          alert('OTP sent to your email')
          localStorage.setItem('resetEmail', this.email)
          this.$router.push('/verify-otp')
        } catch (error) {
          console.error('OTP request failed:', error)
        }
      }
    }
  }
  </script>