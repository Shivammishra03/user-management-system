<template>
    <div class="card">
      <h2 class="text-2xl font-bold text-gray-800 mb-6">Profile</h2>
      <div class="space-y-4">
        <p class="text-gray-700"><span class="font-medium">Name:</span> {{ user.name }}</p>
        <p class="text-gray-700"><span class="font-medium">Email:</span> {{ user.email }}</p>
        <button 
          @click="logout" 
          class="form-button bg-red-600 hover:bg-red-700"
        >
          Logout
        </button>
      </div>
    </div>
  </template>
  
  <script>
  import axios from 'axios'
  import CryptoJS from 'crypto-js'
  import { useCookies } from 'vue3-cookies';
  
  export default {
    data() {
      return {
        user: {}
      }
    },
    setup() {
      const { cookies } = useCookies();
      return { cookies };
    },
    async created() {
      try {
        const response = await axios.get('/api/profile', {
          headers: {
            Authorization: `Bearer ${localStorage.getItem('token')}`
          }
        })
        
        const decryptedData = CryptoJS.AES.decrypt(
          response.data.encryptedData,
          import.meta.env.VITE_ENCRYPTION_KEY
        )
        this.user = JSON.parse(decryptedData.toString(CryptoJS.enc.Utf8))
      } catch (error) {
        console.error('Profile fetch failed:', error)
        this.$router.push('/login')
      }
    },
    methods: {
      logout() {
        localStorage.removeItem('token')
        localStorage.removeItem('twoFactorVerified')
        this.cookies.remove('csrf_token')
        this.$router.push('/login')
      }
    }
  }
  </script>