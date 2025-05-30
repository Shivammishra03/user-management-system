<template>
    <div class="card">
      <h2 class="text-2xl font-bold text-gray-800 mb-6">User Management</h2>
      <table class="table">
        <thead>
          <tr>
            <th>Email</th>
            <th>Name</th>
            <th>Role</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="user in users" :key="user.id">
            <td>{{ user.email }}</td>
            <td>{{ user.name }}</td>
            <td>{{ user.role }}</td>
            <td>
              <button
                @click="editUser(user)"
                class="text-blue-600 hover:text-blue-800 mr-2"
              >
                Edit
              </button>
              <button
                @click="deleteUser(user.id)"
                class="text-red-600 hover:text-red-800"
              >
                Delete
              </button>
            </td>
          </tr>
        </tbody>
      </table>
      <div v-if="editingUser" class="mt-6">
        <h3 class="text-lg font-medium text-gray-800 mb-4">Edit User</h3>
        <form @submit.prevent="updateUser" class="space-y-4">
          <div>
            <label for="name" class="block text-sm font-medium text-gray-700">Name</label>
            <input
              id="name"
              v-model="editingUser.name"
              type="text"
              required
              class="form-input"
            />
          </div>
          <div>
            <label for="role" class="block text-sm font-medium text-gray-700">Role</label>
            <select
              id="role"
              v-model="editingUser.role"
              class="form-input"
            >
              <option value="user">User</option>
              <option value="admin">Admin</option>
            </select>
          </div>
          <div class="flex space-x-4">
            <button type="submit" class="form-button">Update</button>
            <button
              @click="editingUser = null"
              class="form-button bg-gray-600 hover:bg-gray-700"
            >
              Cancel
            </button>
          </div>
        </form>
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
        users: [],
        editingUser: null
      }
    },
    setup() {
      const { cookies } = useCookies();
      return { cookies };
    },
    async created() {
      await this.fetchUsers()
    },
    methods: {
      async fetchUsers() {
        try {
          const response = await axios.get('/api/admin/users', {
            headers: {
              Authorization: `Bearer ${localStorage.getItem('adminToken')}`
            }
          })
          const decryptedData = CryptoJS.AES.decrypt(
            response.data.encryptedData,
            import.meta.env.VITE_ENCRYPTION_KEY
          )
          this.users = JSON.parse(decryptedData.toString(CryptoJS.enc.Utf8))
        } catch (error) {
          console.error('Failed to fetch users:', error)
          this.$router.push('/admin/login')
        }
      },
      editUser(user) {
        this.editingUser = { ...user }
      },
      async updateUser() {
        try {
          const encryptedData = CryptoJS.AES.encrypt(
            JSON.stringify(this.editingUser),
            import.meta.env.VITE_ENCRYPTION_KEY
          ).toString()
          
          await axios.put('/api/admin/users', {
            encryptedData,
            csrfToken: this.cookies.get('csrf_token')
          }, {
            headers: {
              Authorization: `Bearer ${localStorage.getItem('adminToken')}`
            }
          })
          
          this.editingUser = null
          await this.fetchUsers()
          alert('User updated successfully')
        } catch (error) {
          console.error('Failed to update user:', error)
        }
      },
      async deleteUser(userId) {
        if (!confirm('Are you sure you want to delete this user?')) return
  
        try {
          const encryptedData = CryptoJS.AES.encrypt(
            JSON.stringify({ id: userId }),
            'your-encryption-key'
          ).toString()
          
          await axios.delete('/api/admin/users', {
            headers: {
              Authorization: `Bearer ${localStorage.getItem('adminToken')}`
            },
            data: {
              encryptedData,
              csrfToken: this.cookies.get('csrf_token')
            }
          })
          
          await this.fetchUsers()
          alert('User deleted successfully')
        } catch (error) {
          console.error('Failed to delete user:', error)
        }
      }
    }
  }
  </script>