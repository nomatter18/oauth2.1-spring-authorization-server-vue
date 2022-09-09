import Vue from 'vue'
import VueRouter from 'vue-router'

Vue.use(VueRouter)

import HelloWorld from "@/components/HelloWorld"

let router =  new VueRouter({
  routes: [
    {
        name: 'Index',
        path: '/',
        component: HelloWorld
    }  
  ],
  linkActiveClass: 'active',
  mode: 'history',
})

export default router