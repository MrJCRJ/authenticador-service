import request from 'supertest';
import { INestApplication } from '@nestjs/common';
import * as http from 'http';

const SERVER_URL = 'http://localhost:3000';

const checkServerRunning = async (url: string): Promise<boolean> => {
  return new Promise((resolve) => {
    const req = http.get(url, (res) => {
      res.statusCode === 200 ? resolve(true) : resolve(false);
    });

    req.on('error', () => resolve(false)); // Se não conseguir conectar, considera que o servidor não está rodando.
    req.end();
  });
};

describe('AppController (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const isServerRunning = await checkServerRunning(SERVER_URL);

    if (!isServerRunning) {
      console.warn(
        `Servidor não está rodando em ${SERVER_URL}. Testes de integração serão pulados.`,
      );
      return;
    }

    console.log(`Servidor rodando em ${SERVER_URL}. Iniciando testes...`);
    app = {} as INestApplication; // Apenas para passar a tipagem.
  });

  afterAll(async () => {
    if (app && app.close) {
      await app.close();
    }
  });

  it('GET / => deve retornar "Hello World!"', () => {
    if (!app) {
      throw new Error(
        `Servidor não está rodando em ${SERVER_URL}. Teste não pode ser executado.`,
      );
    }

    return request(SERVER_URL) // Conecta o supertest ao servidor em execução
      .get('/') // Faz uma requisição GET para a rota raiz
      .expect(200) // Espera um status HTTP 200 (OK)
      .expect('Hello World!'); // Espera que o corpo da resposta seja "Hello World!"
  });
});
