// src/main.ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import { Logger } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const logger = new Logger('Bootstrap');

  // Middleware para manipulação de cookies.
  app.use(cookieParser());
  logger.log('🍪 Cookie-parser configurado com sucesso!');

  // Configuração do express-session.
  app.use(
    session({
      secret: process.env.SESSION_SECRET || 'sua_chave_secreta_aqui', // Chave secreta para assinar a sessão.
      resave: false, // Evita regravar a sessão se não houver alterações.
      saveUninitialized: false, // Não salva sessões não inicializadas.
      cookie: {
        secure: process.env.NODE_ENV === 'production', // Cookies seguros apenas em produção (HTTPS).
        httpOnly: true, // Impede acesso ao cookie via JavaScript no navegador.
        maxAge: 1000 * 60 * 60 * 24, // Tempo de vida do cookie (1 dia).
        domain: '.vercel.app', // Permite cookies para subdomínios do Vercel
        sameSite: 'lax', // Permite cookies em requisições entre domínios
      },
    }),
  );
  logger.log('🔒 Express-session configurado com sucesso!');

  // Configuração do CORS.
  const allowedOrigins = process.env.FRONTEND_URLS
    ? process.env.FRONTEND_URLS.split(',')
    : ['https://my-history-frontend.vercel.app']; // Domínio do frontend

  app.enableCors({
    origin: allowedOrigins,
    credentials: true, // Permite o envio de cookies
  });
  logger.log('🌍 CORS configurado com sucesso!');

  // Inicia o servidor HTTP.
  const port = process.env.PORT || 3000;
  await app.listen(port);

  // Exibe uma mensagem no console indicando que a aplicação está rodando e em qual porta.
  logger.log(`🚀 Aplicação rodando em: ${await app.getUrl()}`);
  logger.log(`🏁 Ambiente: ${process.env.NODE_ENV || 'development'}`);
}

// Chama a função bootstrap para iniciar a aplicação.
bootstrap().catch((error) => {
  const logger = new Logger('Bootstrap');
  logger.error(`💥 Falha ao iniciar a aplicação: ${error.message}`);
  process.exit(1); // Encerra o processo com código de erro.
});

/**Sugestões de Melhoria (Para Implementar):
Configuração Dinâmica:

Use o ConfigService para carregar configurações dinamicamente (por exemplo, porta, URL do frontend).

typescript
Copy
const configService = app.get(ConfigService);
const port = configService.get<number>('PORT', 3000);
const frontendUrl = configService.get<string>('FRONTEND_URL', 'http://localhost:3000');
Documentação com Swagger:

Adicione o SwaggerModule para documentar a API.

typescript
Copy
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';

const config = new DocumentBuilder()
  .setTitle('API Documentation')
  .setDescription('Descrição da API')
  .setVersion('1.0')
  .build();
const document = SwaggerModule.createDocument(app, config);
SwaggerModule.setup('api', app, document);
Segurança Adicional:

Adicione middlewares de segurança, como helmet e rate-limiting.

typescript
Copy
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

app.use(helmet());
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 100, // Limite de 100 requisições por IP
  }),
);
Monitoramento:

Adicione suporte para ferramentas de monitoramento (por exemplo, Prometheus).

typescript
Copy
import { PrometheusModule } from '@willsoto/nestjs-prometheus';

app.use('/metrics', PrometheusModule.createHandler());
Testes Automatizados:

Adicione testes de integração para garantir que a aplicação inicialize corretamente.

typescript
Copy
describe('Bootstrap', () => {
  it('deve iniciar a aplicação sem erros', async () => {
    await expect(bootstrap()).resolves.not.toThrow();
  });
});
Logs Estruturados:

Use logs estruturados (em formato JSON) para facilitar a análise em ferramentas de monitoramento.

typescript
Copy
logger.log({
  message: 'Aplicação iniciada com sucesso',
  port,
  url: await app.getUrl(),
});
Exemplo de Saída de Logs:
Copy
🍪 Cookie-parser configurado com sucesso!
🌍 CORS configurado com sucesso!
🚀 Aplicação rodando em: http://localhost:3000 */
