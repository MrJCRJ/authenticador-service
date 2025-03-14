// test/auth.e2e-spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from '../../../src/app.module';

describe('AuthController (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it('GET /auth/google => deve redirecionar para o Google OAuth', () => {
    return request(app.getHttpServer())
      .get('/auth/google')
      .expect(302) // Espera um redirecionamento.
      .expect('Location', /accounts\.google\.com/); // Verifica se o redirecionamento é para o Google.
  });

  it('GET /auth/google/callback => deve redirecionar para /auth/profile com token na URL', async () => {
    const response = await request(app.getHttpServer())
      .get('/auth/google/callback')
      .expect(302); // Espera um redirecionamento.

    // Verifica se o redirecionamento é para /auth/profile com token na URL.
    expect(response.header['location']).toMatch(/\/auth\/profile\?token=.+/);
  });

  it('GET /auth/profile?token=<token> => deve retornar os dados do usuário', async () => {
    const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'; // Token JWT válido.

    const response = await request(app.getHttpServer())
      .get(`/auth/profile?token=${token}`)
      .expect(200); // Espera uma resposta bem-sucedida.

    // Verifica se os dados do usuário foram retornados.
    expect(response.body).toHaveProperty('email');
    expect(response.body).toHaveProperty('sub');
  });

  it('GET /auth/profile => deve retornar 401 Unauthorized sem token', async () => {
    await request(app.getHttpServer()).get('/auth/profile').expect(401); // Espera um erro de autenticação.
  });

  it('GET /auth/profile => deve retornar os dados do usuário com token no cookie', async () => {
    const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'; // Token JWT válido.

    const response = await request(app.getHttpServer())
      .get('/auth/profile')
      .set('Cookie', `jwt=${token}`) // Define o token no cookie.
      .expect(200); // Espera uma resposta bem-sucedida.

    // Verifica se os dados do usuário foram retornados.
    expect(response.body).toHaveProperty('email');
    expect(response.body).toHaveProperty('sub');
  });
});
