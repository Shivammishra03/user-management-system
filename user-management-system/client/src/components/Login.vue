<template>
    <div class="card">
      <h2 class="text-2xl font-bold text-gray-800 mb-6">Login</h2>
      <form @submit.prevent="login" class="space-y-4">
        <div>
          <label for="email" class="block text-sm font-medium text-gray-700">Email</label>
          <input
            id="email"
            v-model="form.email"
            type="email"
            required
            class="form-input"
            aria-required="true"
          />
        </div>
        <div>
          <label for="password" class="block text-sm font-medium text-gray-700">Password</label>
          <input
            id="password"
            v-model="form.password"
            type="password"
            required
            class="form-input"
            aria-required="true"
          />
        </div>
        <div>
          <label for="totpCode" class="block text-sm font-medium text-gray-700">2FA Code</label>
          <input
            id="totpCode"
            v-model="form.totpCode"
            type="text"
            required
            class="form-input"
            aria-required="true"
          />
        </div>
        <button type="submit" class="form-button">Login</button>
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
        form: {
          email: '',
          password: '',
          totpCode: ''
        }
      }
    },
    setup() {
      const { cookies } = useCookies();
      return { cookies };
    },
    methods: {
      async login() {
        try {
          const encryptedData = CryptoJS.AES.encrypt(
            JSON.stringify(this.form),
            import.meta.env.VITE_ENCRYPTION_KEY
          ).toString()
          
          const response = await axios.post('/api/login', {
            encryptedData,
            csrfToken: this.cookies.get('csrf_token')
          })
          
          localStorage.setItem('token', response.data.token)
          localStorage.setItem('twoFactorVerified', 'true')
          this.$router.push('/profile')
        } catch (error) {
          console.error('Login failed:', error)
        }
      }
    }
  }
  </script>