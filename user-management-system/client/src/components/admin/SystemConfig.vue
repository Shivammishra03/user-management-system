<template>
    <div class="card">
      <h2 class="text-2xl font-bold text-gray-800 mb-6">System Configuration</h2>
      <form @submit.prevent="updateConfig" class="space-y-4">
        <div>
          <label for="sessionTimeout" class="block text-sm font-medium text-gray-700">Session Timeout (minutes)</label>
          <input
            id="sessionTimeout"
            v-model.number="config.sessionTimeout"
            type="number"
            required
            class="form-input"
          />
        </div>
        <div>
          <label for="maxLoginAttempts" class="block text-sm font-medium text-gray-700">Max Login Attempts</label>
          <input
            id="maxLoginAttempts"
            v-model.number="config.maxLoginAttempts"
            type="number"
            required
            class="form-input"
          />
        </div>
        <button type="submit" class="form-button">Update Configuration</button>
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
        config: {
          sessionTimeout: 60,
          maxLoginAttempts: 5
        }
      }
    },
    setup() {
      const { cookies } = useCookies();
      return { cookies };
    },
    async created() {
      try {
        const response = await axios.get('/api/admin/config', {
          headers: {
            Authorization: `Bearer ${localStorage.getItem('adminToken')}`
          }
        })
        const decryptedData = CryptoJS.AES.decrypt(
          response.data.encryptedData,
          import.meta.env.VITE_ENCRYPTION_KEY
        )
        this.config = JSON.parse(decryptedData.toString(CryptoJS.enc.Utf8))
      } catch (error) {
        console.error('Failed to fetch config:', error)
        this.$router.push('/admin/login')
      }
    },
    methods: {
      async updateConfig() {
        try {
          const encryptedData = CryptoJS.AES.encrypt(
            JSON.stringify(this.config),
            import.meta.env.VITE_ENCRYPTION_KEY
          ).toString()
          
          await axios.put('/api/admin/config', {
            encryptedData,
            csrfToken: this.cookies.get('csrf_token')
          }, {
            headers: {
              Authorization: `Bearer ${localStorage.getItem('adminToken')}`
            }
          })
          
          alert('Configuration updated successfully')
        } catch (error) {
          console.error('Failed to update config:', error)
        }
      }
    }
  }
  </script>