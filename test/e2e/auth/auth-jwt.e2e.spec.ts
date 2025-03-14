// test/auth/auth-jwt.e2e.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from '../../../src/app.module';
import { Logger } from '@nestjs/common';

describe('AuthController (e2e)', () => {
  let app: INestApplication;
  const logger = new Logger('AuthController (e2e)');

  beforeAll(async () => {
    // Cria um módulo de teste com o AppModule.
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    // Inicializa a aplicação NestJS.
    app = moduleFixture.createNestApplication();
    await app.init();

    logger.log('🚀 Aplicação inicializada para testes E2E.');
  });

  afterAll(async () => {
    // Encerra a aplicação após os testes.
    await app.close();
    logger.log('🛑 Aplicação encerrada após testes E2E.');
  });

  it('GET /auth/google => deve redirecionar para o Google OAuth', () => {
    logger.log('🔍 Testando redirecionamento para o Google OAuth...');

    return request(app.getHttpServer())
      .get('/auth/google')
      .expect(302) // Espera um redirecionamento.
      .expect('Location', /accounts\.google\.com/); // Verifica se o redirecionamento é para o Google.
  });

  it('GET /auth/google/callback => deve redirecionar para /auth/profile com token na URL', async () => {
    logger.log('🔍 Testando callback do Google OAuth...');

    const response = await request(app.getHttpServer())
      .get('/auth/google/callback')
      .expect(302); // Espera um redirecionamento.

    // Verifica se o redirecionamento é para /auth/profile com token na URL.
    expect(response.header['location']).toMatch(/\/auth\/profile\?token=.+/);

    logger.log('✅ Callback do Google OAuth testado com sucesso.');
  });

  it('GET /auth/profile?token=<token> => deve retornar os dados do usuário', async () => {
    logger.log('🔍 Testando acesso ao perfil com token na URL...');

    const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'; // Token JWT válido.

    const response = await request(app.getHttpServer())
      .get(`/auth/profile?token=${token}`)
      .expect(200); // Espera uma resposta bem-sucedida.

    // Verifica se os dados do usuário foram retornados.
    expect(response.body).toHaveProperty('email');
    expect(response.body).toHaveProperty('sub');

    logger.log('✅ Acesso ao perfil com token na URL testado com sucesso.');
  });

  it('GET /auth/profile => deve retornar 401 Unauthorized sem token', async () => {
    logger.log('🔍 Testando acesso ao perfil sem token...');

    await request(app.getHttpServer()).get('/auth/profile').expect(401); // Espera um erro de autenticação.

    logger.log('✅ Acesso ao perfil sem token testado com sucesso.');
  });

  it('GET /auth/profile => deve retornar os dados do usuário com token no cookie', async () => {
    logger.log('🔍 Testando acesso ao perfil com token no cookie...');

    const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'; // Token JWT válido.

    const response = await request(app.getHttpServer())
      .get('/auth/profile')
      .set('Cookie', `jwt=${token}`) // Define o token no cookie.
      .expect(200); // Espera uma resposta bem-sucedida.

    // Verifica se os dados do usuário foram retornados.
    expect(response.body).toHaveProperty('email');
    expect(response.body).toHaveProperty('sub');

    logger.log('✅ Acesso ao perfil com token no cookie testado com sucesso.');
  });
});

/**puração em caso de falhas nos testes.

Sugestões de Melhoria (Para Implementar):
Mock de Dados:

Use mocks para simular o comportamento do Google OAuth e do JWT.

typescript
Copy
jest.mock('@nestjs/passport', () => ({
  AuthGuard: () => jest.fn().mockImplementation(() => true),
}));
Testes de Erros:

Adicione testes para cenários de erro, como tokens inválidos ou expirados.

typescript
Copy
it('GET /auth/profile?token=<token-invalido> => deve retornar 401 Unauthorized', async () => {
  const token = 'token-invalido';
  await request(app.getHttpServer())
    .get(`/auth/profile?token=${token}`)
    .expect(401);
});
Configuração Dinâmica:

Use o ConfigService para carregar configurações dinamicamente (por exemplo, URL do Google OAuth).

typescript
Copy
const googleOAuthUrl = configService.get<string>('GOOGLE_OAUTH_URL');
expect(response.header['location']).toMatch(new RegExp(googleOAuthUrl));
Testes de Performance:

Adicione testes de performance para garantir que a autenticação seja eficiente.

typescript
Copy
it('GET /auth/profile => deve responder em menos de 100ms', async () => {
  const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...';
  const start = Date.now();
  await request(app.getHttpServer())
    .get('/auth/profile')
    .set('Cookie', `jwt=${token}`);
  const duration = Date.now() - start;
  expect(duration).toBeLessThan(100);
});
Cobertura de Testes:

Use ferramentas como jest --coverage para garantir que todos os cenários sejam testados.

Testes de Segurança:

Adicione testes para verificar a segurança da aplicação (por exemplo, proteção contra CSRF).

typescript
Copy
it('GET /auth/profile => deve rejeitar tokens malformados', async () => {
  const token = 'malformado';
  await request(app.getHttpServer())
    .get('/auth/profile')
    .set('Cookie', `jwt=${token}`)
    .expect(401);
});
Exemplo de Saída de Logs:
Copy
🚀 Aplicação inicializada para testes E2E.
🔍 Testando redirecionamento para o Google OAuth...
🔍 Testando callback do Google OAuth...
✅ Callback do Google OAuth testado com sucesso.
🔍 Testando acesso ao perfil com token na URL...
✅ Acesso ao perfil com token na URL testado com sucesso.
🔍 Testando acesso ao perfil sem token...
✅ Acesso ao perfil sem token testado com sucesso.
🔍 Testando acesso ao perfil com token no cookie...
✅ Acesso ao perfil com token no cookie testado com sucesso.
🛑 Aplicação encerrada após testes E2E. */
