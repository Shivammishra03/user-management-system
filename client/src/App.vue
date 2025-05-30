<template>
  <div class="min-h-screen bg-gray-100">
    <header class="bg-white shadow-sm">
      <nav class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
        <div class="flex justify-between items-center">
          <div class="text-xl font-bold text-gray-800">Government Portal</div>
          <div class="space-x-4">
            <router-link to="/register" class="nav-link">Register</router-link>
            <router-link to="/login" class="nav-link">Login</router-link>
            <router-link to="/profile" class="nav-link">Profile</router-link>
            <router-link to="/forgot-password" class="nav-link">Forgot Password</router-link>
            <router-link to="/change-password" class="nav-link">Change Password</router-link>
            <router-link to="/two-factor-setup" class="nav-link">2FA Setup</router-link>
            <router-link to="/admin/login" class="nav-link">Admin</router-link>
          </div>
        </div>
      </nav>
    </header>
    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <router-view></router-view>
    </main>
  </div>
</template>