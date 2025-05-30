import { createRouter, createWebHistory } from 'vue-router'
import Register from '@/components/Register.vue'
import Login from '@/components/Login.vue'
import Profile from '@/components/Profile.vue'
import ForgotPassword from '@/components/ForgotPassword.vue'
import VerifyOtp from '@/components/VerifyOtp.vue'
import ResetPassword from '@/components/ResetPassword.vue'
import ChangePassword from '@/components/ChangePassword.vue'
import TwoFactorSetup from '@/components/TwoFactorSetup.vue'
import AdminLogin from '@/components/admin/AdminLogin.vue'
import AdminDashboard from '@/components/admin/AdminDashboard.vue'
import UserManagement from '@/components/admin/UserManagement.vue'
import AuditLogs from '@/components/admin/AuditLogs.vue'
import SystemConfig from '@/components/admin/SystemConfig.vue'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    { path: '/register', component: Register },
    { path: '/login', component: Login },
    { path: '/profile', component: Profile, meta: { requiresAuth: true, requires2FA: true } },
    { path: '/forgot-password', component: ForgotPassword },
    { path: '/verify-otp', component: VerifyOtp },
    { path: '/reset-password', component: ResetPassword, meta: { requiresOtp: true } },
    { path: '/change-password', component: ChangePassword, meta: { requiresAuth: true, requires2FA: true } },
    { path: '/two-factor-setup', component: TwoFactorSetup, meta: { requiresAuth: true } },
    { path: '/admin/login', component: AdminLogin },
    { path: '/admin/dashboard', component: AdminDashboard, meta: { requiresAdmin: true } },
    { path: '/admin/users', component: UserManagement, meta: { requiresAdmin: true } },
    { path: '/admin/audit-logs', component: AuditLogs, meta: { requiresAdmin: true } },
    { path: '/admin/config', component: SystemConfig, meta: { requiresAdmin: true } }
  ],
})

router.beforeEach((to, from, next) => {
  const authToken = localStorage.getItem('token')
  const otpToken = localStorage.getItem('otpToken')
  const twoFactorVerified = localStorage.getItem('twoFactorVerified')
  const adminToken = localStorage.getItem('adminToken')

  if (to.meta.requiresAuth && !authToken) {
    next('/login')
  } else if (to.meta.requiresOtp && !otpToken) {
    next('/forgot-password')
  } else if (to.meta.requires2FA && !twoFactorVerified) {
    next('/two-factor-setup')
  } else if (to.meta.requiresAdmin && !adminToken) {
    next('/admin/login')
  } else {
    next()
  }
})

export default router
