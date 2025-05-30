<template>
    <div class="card">
      <h2 class="text-2xl font-bold text-gray-800 mb-6">Register</h2>
      <form @submit.prevent="register" class="space-y-4">
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
          <p v-if="passwordError" class="error text-red-600 text-sm mt-1">{{ passwordError }}</p>
        </div>
        <div>
          <label for="name" class="block text-sm font-medium text-gray-700">Name</label>
          <input
            id="name"
            v-model="form.name"
            type="text"
            required
            class="form-input"
            aria-required="true"
          />
        </div>
        <button type="submit" class="form-button bg-blue-500 hover:bg-blue-600 text-white py-2 px-4 rounded">
          Register
        </button>
      </form>
    </div>
  </template>
  
  <script setup>
  import { ref, onMounted} from 'vue'
  import { useRouter } from 'vue-router'
  import { useCookies } from 'vue3-cookies'
  import axios from 'axios'
  import CryptoJS from 'crypto-js'
  
  const form = ref({
    email: '',
    password: '',
    name: ''
  })
  
  const passwordError = ref('')
  const router = useRouter()
  const { cookies } = useCookies()
  
  const validatePassword = (password) => {
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
  }
  
  const register = async () => {
    passwordError.value = validatePassword(form.value.password)
    if (passwordError.value) return  
    try {
      const encryptedData = CryptoJS.AES.encrypt(
        JSON.stringify(form.value),
        import.meta.env.VITE_ENCRYPTION_KEY || 'fallback-key'
      ).toString()
  
      const response = await axios.post(
        '/api/register',
        {
          encryptedData,
          csrfToken: cookies.get('csrf_token') // Fetch fresh on submit
        },
        { withCredentials: true } // Needed if CSRF cookie is httpOnly
      )
  
      localStorage.setItem('token', response.data.token)
      router.push('/two-factor-setup')
    } catch (error) {
      console.error('Registration failed:', error)
    }
  }
  const getcsrfToken = async()=> {
    const csrfTokenRespo = await axios.get('/api/csrf-token',{ withCredentials: true });

  }
  onMounted(() => {
    getcsrfToken();
  });
  </script>
  
  <style scoped>
  .form-input {
    width: 100%;
    padding: 0.5rem;
    border: 1px solid #d1d5db;
    border-radius: 0.375rem;
  }
  .error {
    color: red;
    font-size: 0.875rem;
  }
  </style>
  