### Testes Manuais

1. **Autenticação via Google OAuth:**

   - Acesse `/auth/google`.
   - Faça login com uma conta Google.
   - Verifique se o redirecionamento para `/auth/profile` ocorre com um token na URL.

2. **Acesso ao Perfil com Token:**

   - Acesse `/auth/profile?token=<token>`.
   - Verifique se os dados do usuário são retornados.

3. **Acesso ao Perfil com Cookie:**
   - Acesse `/auth/profile` com o cookie `jwt=<token>`.
   - Verifique se os dados do usuário são retornados.
