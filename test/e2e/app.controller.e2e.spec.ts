// src/auth/auth.e2e.spec.ts
import request from 'supertest';
import { INestApplication } from '@nestjs/common';
import * as http from 'http';
import { Logger } from '@nestjs/common';

/**
 * URL do servidor a ser testado.
 */
const SERVER_URL = 'http://localhost:3000';

/**
 * Logger personalizado para os testes E2E, com emojis para logs divertidos e intuitivos 🎉
 */
const logger = new Logger('AppController (e2e)');

/**
 * Verifica se o servidor está rodando na URL especificada.
 *
 * @param url - URL do servidor.
 * @returns `true` se o servidor estiver rodando, `false` caso contrário.
 */
const checkServerRunning = async (url: string): Promise<boolean> => {
  return new Promise((resolve) => {
    const req = http.get(url, (res) => {
      res.statusCode === 200 ? resolve(true) : resolve(false);
    });

    req.on('error', () => resolve(false)); // Se não conseguir conectar, considera que o servidor não está rodando.
    req.end();
  });
};

/**
 * Testes de integração (e2e) para o AppController.
 * Este teste verifica se o servidor está rodando e executa testes de integração.
 */
describe('AppController (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    // Verifica se o servidor está rodando.
    const isServerRunning = await checkServerRunning(SERVER_URL);

    if (!isServerRunning) {
      logger.warn(
        `⚠️ Servidor não está rodando em ${SERVER_URL}. Testes de integração serão pulados.`,
      );
      return;
    }

    logger.log(`🚀 Servidor rodando em ${SERVER_URL}. Iniciando testes...`);
    app = {} as INestApplication; // Apenas para passar a tipagem.
  });

  afterAll(async () => {
    // Encerra a aplicação após os testes.
    if (app && app.close) {
      await app.close();
      logger.log('🛑 Aplicação encerrada após testes E2E.');
    }
  });

  /**
   * Testa a rota raiz da aplicação.
   * Verifica se a rota retorna "Hello World!".
   */
  it('GET / => deve retornar "Hello World!"', () => {
    if (!app) {
      throw new Error(
        `❌ Servidor não está rodando em ${SERVER_URL}. Teste não pode ser executado.`,
      );
    }

    logger.log('🔍 Testando rota raiz da aplicação...');

    return request(SERVER_URL) // Conecta o supertest ao servidor em execução.
      .get('/') // Faz uma requisição GET para a rota raiz.
      .expect(200) // Espera um status HTTP 200 (OK).
      .expect('Hello World!') // Espera que o corpo da resposta seja "Hello World!".
      .then(() => {
        logger.log('✅ Rota raiz testada com sucesso.');
      });
  });
});

/**Sugestões de Melhoria (Para Implementar):
Mock de Dados:

Use mocks para simular o comportamento do servidor em testes unitários.

typescript
Copy
jest.mock('@nestjs/core', () => ({
  NestFactory: {
    create: jest.fn().mockImplementation(() => ({
      listen: jest.fn().mockResolvedValue({}),
    })),
  },
}));
Testes de Erros:

Adicione testes para cenários de erro, como falhas no servidor.

typescript
Copy
it('GET / => deve retornar 500 em caso de erro no servidor', async () => {
  jest.spyOn(AppController.prototype, 'getHello').mockImplementation(() => {
    throw new Error('Erro no servidor');
  });

  await request(SERVER_URL).get('/').expect(500);
});
Configuração Dinâmica:

Use variáveis de ambiente para configurar a URL do servidor.

typescript
Copy
const SERVER_URL = process.env.SERVER_URL || 'http://localhost:3000';
Testes de Performance:

Adicione testes de performance para garantir que a rota raiz seja eficiente.

typescript
Copy
it('GET / => deve responder em menos de 100ms', async () => {
  const start = Date.now();
  await request(SERVER_URL).get('/').expect(200);
  const duration = Date.now() - start;
  expect(duration).toBeLessThan(100);
});
Cobertura de Testes:

Use ferramentas como jest --coverage para garantir que todos os cenários sejam testados.

Testes de Segurança:

Adicione testes para verificar a segurança da aplicação (por exemplo, proteção contra CSRF).

typescript
Copy
it('GET / => deve rejeitar requisições sem cabeçalhos de segurança', async () => {
  await request(SERVER_URL)
    .get('/')
    .set('X-Requested-With', 'XMLHttpRequest')
    .expect(403);
});
Exemplo de Saída de Logs:
Copy
⚠️ Servidor não está rodando em http://localhost:3000. Testes de integração serão pulados.
Ou, se o servidor estiver rodando:

Copy
🚀 Servidor rodando em http://localhost:3000. Iniciando testes...
🔍 Testando rota raiz da aplicação...
✅ Rota raiz testada com sucesso.
🛑 Aplicação encerrada após testes E2E.
 */
