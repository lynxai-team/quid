<template>
  <div class="absolute top-0 left-0 w-screen h-screen overflow-hidden bg-cover bg-steel login">
    <div class="container inset-0 flex justify-center flex-1 h-full mx-auto mt-8">
      <div class="w-full max-w-lg">
        <form class="max-w-sm p-10 space-y-5 bg-white bg-opacity-25 rounded shadow-xl" id="login-form">
          <p class="text-lg font-bold text-center text-white">
            <i class="fas fa-user-shield"></i>&nbsp;&nbsp;LOGIN
          </p>
          <div>
            <label class="block text-sm text-white">Namespace</label>
            <sw-input id="namespace" v-model:value="form.namespace.val" v-model:isvalid="form.namespace.isValid"
              :validator="form.namespace.validator" @update:value="mChange($event)" placeholder="namespace" required>
            </sw-input>
          </div>
          <div class="mt-2">
            <label class="block text-sm text-white">Username</label>
            <sw-input id="username" v-model:value="form.name.val" v-model:isvalid="form.name.isValid"
              :validator="form.name.validator" @update:value="mChange($event)" placeholder="username" required>
            </sw-input>
          </div>
          <div class="mt-2">
            <label class="block text-sm text-white">Password</label>
            <sw-input id="password" v-model:value="form.password.val" v-model:isvalid="form.password.isValid"
              :validator="form.password.validator" @update:value="mChange($event)" type="password"
              placeholder="password" required></sw-input>
          </div>

          <div class="flex items-center justify-end mt-8">
            <button class="btn primary" :disabled="!isFormValid" @click.prevent="login()">Submit</button>
          </div>
          <!-- div class="text-center">
              <a
                class="right-0 inline-block text-sm font-light align-baseline text-500 hover:text-red-400"
              >
                Créer un compte
              </a>
          </div-->
        </form>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { computed, defineComponent, reactive } from "vue";
import { Emo } from "emosd";
import SwInput from "@snowind/input";
import { user } from "@/state";
import { adminLogin } from "@/api";

export default defineComponent({
  components: {
    SwInput,
  },
  emits: ["end"],
  // eslint-disable-next-line
  setup(props, { emit }) {
    const emo = new Emo({ zone: "TheLogin" });

    const form = reactive({
      namespace: {
        val: "",
        isValid: false,
        // eslint-disable-next-line
        validator: (v: string) => v.length >= 1,
      },
      name: {
        val: "",
        isValid: false,
        // eslint-disable-next-line
        validator: (v: string) => v.length >= 1,
      },
      password: {
        val: "",
        isValid: false,
        // eslint-disable-next-line
        validator: (v: string) => v.length >= 3,
      },
    });

    const isFormValid = computed<boolean>(() => {
      return form.namespace.isValid && form.name.isValid && form.password.isValid;
    });

    // eslint-disable-next-line
    function mChange(v: any) {
      //console.log("Mchange", v);
      console.log(isFormValid.value);
    }

    async function login() {
      try {
        emo.requestPost("Getting a refresh token");
      } catch (e) {
        emo.error(`Error getting refresh token ${e}`);
      }
      const ok = await adminLogin(form.namespace.val, form.name.val, form.password.val);
      if (!ok) { return }
      emo.ok("Logging in");
      user.isLoggedIn.value = true;
      emit("end");
    }

    function cancel() {
      emit("end");
    }

    return {
      login,
      cancel,
      form,
      mChange,
      isFormValid,
    };
  },
});
</script>

<style lang="sass">
.login
  background-repeat: no-repeat
  background-size: cover
#login-form
  & input
    @apply bg-gray-200 w-full
</style>