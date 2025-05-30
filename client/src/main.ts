import { createApp } from 'vue'
import { createPinia } from 'pinia'
// import { useCookies } from 'vue3-cookies'  // Just import the `useCookies` function
import axios from 'axios'
import App from './App.vue'
import router from './router'
import '@/assets/style.css'

const app = createApp(App)

app.use(createPinia())
app.use(router)
// app.use(useCookies)
app.mount('#app')

// No need to use `app.use(VueCookies)`
// Instead, you can directly use `useCookies` in your components.
