<template>
  <v-app>
    <v-app-bar
      app
      color="primary"
      dark
    >
      <div class="d-flex align-center">
        <v-img
          alt="Vuetify Logo"
          class="shrink mr-2"
          contain
          src="https://cdn.vuetifyjs.com/images/logos/vuetify-logo-dark.png"
          transition="scale-transition"
          width="40"
        />

        <v-img
          alt="Vuetify Name"
          class="shrink mt-1 hidden-sm-and-down"
          contain
          min-width="100"
          src="https://cdn.vuetifyjs.com/images/logos/vuetify-name-dark.png"
          width="100"
        />
      </div>

      <v-spacer></v-spacer>

      <v-btn @click="resource()">Resource</v-btn>
      <v-btn @click="login()">Login</v-btn>

      <v-btn
        href="https://github.com/vuetifyjs/vuetify/releases/latest"
        target="_blank"
        text
      >
        <span class="mr-2">Latest Release</span>
        <v-icon>mdi-open-in-new</v-icon>
      </v-btn>
    </v-app-bar>

    <v-main>
      <router-view/>
    </v-main>
  </v-app>
</template>

<script>
import axios from 'axios'
export default {
  name: 'App',

  components: {
  },

  data: () => ({
    //
  }),

  methods: {
    init(){

    },

    resource(){
      axios.get('http://127.0.0.1:8080/api/',
        {
          headers: {
            'Content-type':'application/url-form-encoded',
            'Authorization':'Bearer '+window.sessionStorage.getItem("_a")
          }
      }).then(data => {
        console.log(data)
      }).catch(e => console.log(e))
    },

    login() {
      var codeVerifier = this.generateRandomString(64);

      Promise.resolve()
          .then(() => {
            return this.generateCodeChallenge(codeVerifier)
          })
          .then(function(codeChallenge) {
              window.sessionStorage.setItem("code_verifier", codeVerifier)

              let args = new URLSearchParams({
                  response_type: "code",
                  client_id: 'browser-client',
                  redirect_uri: 'http://127.0.0.1:8081/code',
                  state: '1234zyx',
                  code_challenge: codeChallenge,
                  code_challenge_method: 'S256',
                  scope: 'openid browser.read'
              });
              window.location = "http://127.0.0.1:9000/oauth2/authorize?" + args;
      });
    },

    async generateCodeChallenge(codeVerifier) {
        var digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier));
        return btoa(String.fromCharCode(...new Uint8Array(digest)))
            .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
    },

    generateRandomString(length) {
        var text = "";
        var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        for (var i = 0; i < length; i++) {
            text += possible.charAt(Math.floor(Math.random() * possible.length));
        }

        return text;
    }
  }
};
</script>
