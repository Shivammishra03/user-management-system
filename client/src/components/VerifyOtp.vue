<template>
    <div class="card">
      <h2 class="text-2xl font-bold text-gray-800 mb-6">Verify OTP</h2>
      <form @submit.prevent="verifyOtp" class="space-y-4">
        <div>
          <label for="otp" class="block text-sm font-medium text-gray-700">OTP</label>
          <input
            id="otp"
            v-model="otp"
            type="text"
            required
            class="form-input"
            aria-required="true"
          />
        </div>
        <button type="submit" class="form-button">Verify OTP</button>
      </form>
    </div>
  </template>
  
  <script>
  import axios from 'axios'
  import CryptoJS from 'crypto-js'
  
  export default {
    data() {
      return {
        otp: ''
      }
    },
    methods: {
      async verifyOtp() {
        try {
          const email = localStorage.getItem('resetEmail')
          const encryptedData = CryptoJS.AES.encrypt(
            JSON.stringify({ email, otp: this.otp }),
            'your-encryption-key'
          ).toString()
          
          const response = await axios.post('/api/verify-otp', { 
            encryptedData,
            csrfToken: this.cookies.get('csrf_token')
          })
          localStorage.setItem('otpToken', response.data.otpToken)
          this.$router.push('/reset-password')
        } catch (error) {
          console.error('OTP verification failed:', error)
          alert('Invalid or expired OTP')
        }
      }
    }
  }
  </script>