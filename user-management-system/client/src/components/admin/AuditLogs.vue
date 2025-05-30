<template>
    <div class="card">
      <h2 class="text-2xl font-bold text-gray-800 mb-6">Audit Logs</h2>
      <table class="table">
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>User Email</th>
            <th>Action</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="log in logs" :key="log.id">
            <td>{{ formatDate(log.created_at) }}</td>
            <td>{{ log.user_email }}</td>
            <td>{{ log.action }}</td>
            <td>{{ log.details }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </template>
  
  <script>
  import axios from 'axios'
  import CryptoJS from 'crypto-js'
  
  export default {
    data() {
      return {
        logs: []
      }
    },
    async created() {
      try {
        const response = await axios.get('/api/admin/audit-logs', {
          headers: {
            Authorization: `Bearer ${localStorage.getItem('adminToken')}`
          }
        })
        const decryptedData = CryptoJS.AES.decrypt(
          response.data.encryptedData,
          import.meta.env.VITE_ENCRYPTION_KEY
        )
        this.logs = JSON.parse(decryptedData.toString(CryptoJS.enc.Utf8))
      } catch (error) {
        console.error('Failed to fetch audit logs:', error)
        this.$router.push('/admin/login')
      }
    },
    methods: {
      formatDate(date) {
        return new Date(date).toLocaleString()
      }
    }
  }
  </script>