<template>
    <div class="card">
      <h2 class="text-2xl font-bold text-gray-800 mb-6">Admin Dashboard</h2>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <router-link
          to="/admin/users"
          class="bg-blue-100 p-4 rounded-lg text-center hover:bg-blue-200 transition-colors"
        >
          <h3 class="text-lg font-medium text-gray-800">User Management</h3>
          <p class="text-gray-600">Manage user accounts</p>
        </router-link>
        <router-link
          to="/admin/audit-logs"
          class="bg-blue-100 p-4 rounded-lg text-center hover:bg-blue-200 transition-colors"
        >
          <h3 class="text-lg font-medium text-gray-800">Audit Logs</h3>
          <p class="text-gray-600">View system activity</p>
        </router-link>
        <router-link
          to="/admin/config"
          class="bg-blue-100 p-4 rounded-lg text-center hover:bg-blue-200 transition-colors"
        >
          <h3 class="text-lg font-medium text-gray-800">System Configuration</h3>
          <p class="text-gray-600">Manage system settings</p>
        </router-link>
      </div>
      <button
        @click="logout"
        class="form-button bg-red-600 hover:bg-red-700 mt-6"
      >
        Logout
      </button>
    </div>
  </template>
  
  <script>
  import { useCookies } from 'vue3-cookies';

  export default {
    setup() {
      const { cookies } = useCookies();
      return { cookies };
    },
    methods: {
      logout() {
        localStorage.removeItem('adminToken')
        this.cookies.remove('csrf_token')
        this.$router.push('/admin/login')
      }
    }
  }
  </script>