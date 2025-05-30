<template>
    <div class="card">
      <h2 class="text-2xl font-bold text-gray-800 mb-6">Two-Factor Authentication Setup</h2>
      <div v-if="qrCode" class="mb-6">
        <img :src="qrCode" alt="2FA QR Code" class="mx-auto" />
        <p class="text-gray-600 text-center mt-2">Scan this QR code with your authenticator app</p>
      </div>
      <form @submit.prevent="verifyTotp" class="space-y-4">
        <div>
          <label for="totpCode" class="block text-sm font-medium text-gray-700">2FA Code</label>
          <input
            id="totpCode"
            v-model="totpCode"
            type="text"
            required
            class="form-input"
            aria-required="true"
          />
        </div>
        <button type="submit" class="form-button">Verify</button>
      </form>
    </div>
  </template>
  
  <script>
  import axios from 'axios'
  import CryptoJS from 'crypto-js'
  import { useCookies } from 'vue3-cookies';
  
  export default {
    data() {
      return {
        qrCode: '',
        totpCode: ''
      }
    },
    setup() {
      const { cookies } = useCookies();
      return { cookies };
    },
    async created() {
      try {
        const response = await axios.get('/api/two-factor-setup', {
          headers: {
            Authorization: `Bearer ${localStorage.getItem('token')}`
          }
        })
        this.qrCode = response.data.qrCode
      } catch (error) {
        console.error('2FA setup failed:', error)
      }
    },
    methods: {
      async verifyTotp() {
        try {
          const encryptedData = CryptoJS.AES.encrypt(
            this.totpCode,
            import.meta.env.VITE_ENCRYPTION_KEY
          ).toString()
          
          await axios.post('/api/verify-totp', {
            encryptedData,
            csrfToken: this.cookies.get('csrf_token')
          }, {
            headers: {
              Authorization: `Bearer ${localStorage.getItem('token')}`
            }
          })
          
          localStorage.setItem('twoFactorVerified', 'true')
          this.$router.push('/profile')
        } catch (error) {
          console.error('2FA verification failed:', error)
        }
      }
    }
  }
  </script>