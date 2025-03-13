import request from 'supertest';

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
 * Testes de integração (e2e) para o AuthController.
 * Este teste assume que o servidor está rodando.
 */
describe('AuthController (e2e)', () => {
  /**
   * Testa a rota /auth/google.
   * Verifica se redireciona para a URL de autenticação do Google.
   */
  it('GET /auth/google => deve redirecionar para o Google OAuth', async () => {
    const response = await request(SERVER_URL).get(GOOGLE_AUTH_URL).expect(302); // Espera um redirecionamento

    // Verifica se o redirecionamento é para a URL de autenticação do Google
    expect(response.header['location']).toContain(GOOGLE_OAUTH_URL);
  });

  /**
   * Testa a rota /auth/google/callback.
   * Verifica se redireciona corretamente quando não há token.
   */
  it('GET /auth/google/callback => deve redirecionar se não houver token', async () => {
    const response = await request(SERVER_URL)
      .get(GOOGLE_CALLBACK_URL)
      .expect(302); // Espera um redirecionamento

    // Verifica se há um redirecionamento
    expect(response.header['location']).toBeDefined();
  });
});
