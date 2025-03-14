// src/auth/auth.e2e.spec.ts
import request from 'supertest';
import { Logger } from '@nestjs/common';

/**
 * URL do servidor a ser testado.
 */
const SERVER_URL = 'http://localhost:3000';

/**
 * Constantes para URLs e valores esperados.
 */
const GOOGLE_AUTH_URL = '/auth/google';
const GOOGLE_CALLBACK_URL = '/auth/google/callback';
const GOOGLE_OAUTH_URL = 'https://accounts.google.com/o/oauth2';

/**
 * Logger personalizado para os testes E2E, com emojis para logs divertidos e intuitivos 🎉
 */
const logger = new Logger('AuthController (e2e)');

/**
 * Testes de integração (e2e) para o AuthController.
 * Este teste assume que o servidor está rodando.
 */
describe('AuthController (e2e)', () => {
  /**
   * Testa a rota /auth/google.
   * Verifica se redireciona para a URL de autenticação do Google.
   */
  it('GET /auth/google => deve redirecionar para o Google OAuth', async () => {
    logger.log('🔍 Testando redirecionamento para o Google OAuth...');

    const response = await request(SERVER_URL).get(GOOGLE_AUTH_URL).expect(302); // Espera um redirecionamento.

    // Verifica se o redirecionamento é para a URL de autenticação do Google.
    expect(response.header['location']).toContain(GOOGLE_OAUTH_URL);

    logger.log('✅ Redirecionamento para o Google OAuth testado com sucesso.');
  });

  /**
   * Testa a rota /auth/google/callback.
   * Verifica se redireciona corretamente quando não há token.
   */
  it('GET /auth/google/callback => deve redirecionar se não houver token', async () => {
    logger.log('🔍 Testando callback do Google sem token...');

    const response = await request(SERVER_URL)
      .get(GOOGLE_CALLBACK_URL)
      .expect(302); // Espera um redirecionamento.

    // Verifica se há um redirecionamento.
    expect(response.header['location']).toBeDefined();

    logger.log('✅ Callback do Google sem token testado com sucesso.');
  });
});

/**Sugestões de Melhoria (Para Implementar):
Mock de Dados:

Use mocks para simular o comportamento do Google OAuth.

typescript
Copy
jest.mock('@nestjs/passport', () => ({
  AuthGuard: () => jest.fn().mockImplementation(() => true),
}));
Testes de Erros:

Adicione testes para cenários de erro, como falhas no redirecionamento.

typescript
Copy
it('GET /auth/google => deve retornar 500 em caso de erro no servidor', async () => {
  jest.spyOn(AuthService.prototype, 'googleAuth').mockImplementation(() => {
    throw new Error('Erro no servidor');
  });

  await request(SERVER_URL).get(GOOGLE_AUTH_URL).expect(500);
});
Configuração Dinâmica:

Use variáveis de ambiente para configurar URLs e valores esperados.

typescript
Copy
const GOOGLE_OAUTH_URL = process.env.GOOGLE_OAUTH_URL || 'https://accounts.google.com/o/oauth2';
Testes de Performance:

Adicione testes de performance para garantir que o redirecionamento seja eficiente.

typescript
Copy
it('GET /auth/google => deve responder em menos de 100ms', async () => {
  const start = Date.now();
  await request(SERVER_URL).get(GOOGLE_AUTH_URL).expect(302);
  const duration = Date.now() - start;
  expect(duration).toBeLessThan(100);
});
Cobertura de Testes:

Use ferramentas como jest --coverage para garantir que todos os cenários sejam testados.

Testes de Segurança:

Adicione testes para verificar a segurança da aplicação (por exemplo, proteção contra CSRF).

typescript
Copy
it('GET /auth/google => deve rejeitar requisições sem cabeçalhos de segurança', async () => {
  await request(SERVER_URL)
    .get(GOOGLE_AUTH_URL)
    .set('X-Requested-With', 'XMLHttpRequest')
    .expect(403);
});
Exemplo de Saída de Logs:
Copy
🔍 Testando redirecionamento para o Google OAuth...
✅ Redirecionamento para o Google OAuth testado com sucesso.
🔍 Testando callback do Google sem token...
✅ Callback do Google sem token testado com sucesso. */
