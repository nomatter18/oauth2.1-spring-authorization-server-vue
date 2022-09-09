import Vue from 'vue'
import App from './App.vue'
import vuetify from './plugins/vuetify'
import router from './router'
import axios from 'axios'

Vue.config.productionTip = false

// var _a = '';

router.beforeEach((to, from, next) => {
  if (to.path == '/code' && to.query.code != null) {
    let formData = new FormData()
    formData.append('grant_type','authorization_code')
    formData.append('code',to.query.code)
    formData.append('redirect_uri','http://127.0.0.1:8081/code')
    formData.append('client_id','browser-client')
    formData.append('code_verifier',window.sessionStorage.getItem("code_verifier"))

    axios.post('http://127.0.0.1:9000/oauth2/token',
    formData,
    {
      headers: {
        'Content-type':'application/url-form-encoded',
        'Authorization':'Basic '+btoa('browser-client:secret')
      }
    }
    ).then(resp => {
      console.log(resp.data)
      window.sessionStorage.setItem("_a", resp.data.access_token);
    })
    next({name: 'Index'})
  } else {
    next()
  }
})

new Vue({
  vuetify,
  router,
  render: h => h(App)
}).$mount('#app')
