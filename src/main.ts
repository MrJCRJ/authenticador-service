// src/main.ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import { Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);
  const logger = new Logger('Bootstrap');

  // Middleware para manipulação de cookies
  app.use(cookieParser());
  logger.log('🍪 Cookie-parser configurado com sucesso!');

  // Configuração do express-session
  app.use(
    session({
      secret: configService.get('SESSION_SECRET') || 'sua_chave_secreta_aqui',
      resave: false,
      saveUninitialized: false,
      cookie: {
        secure: configService.get('NODE_ENV') === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 1 dia
        sameSite:
          configService.get('NODE_ENV') === 'production' ? 'none' : 'lax',
        ...(configService.get('NODE_ENV') === 'production' && {
          domain: configService.get('COOKIE_DOMAIN'),
        }),
      },
    }),
  );
  logger.log('🔒 Express-session configurado com sucesso!');

  // Configuração robusta do CORS
  const allowedOrigins = [
    'http://localhost:5500',
    'http://127.0.0.1:5500',
    ...(configService.get('FRONTEND_URLS')?.split(',') || []),
  ].filter(Boolean);

  app.enableCors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        logger.warn(
          `⚠️ Tentativa de acesso de origem não permitida: ${origin}`,
        );
        callback(new Error('Not allowed by CORS'));
      }
    },
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
    credentials: true,
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Requested-With',
      'Accept',
    ],
    exposedHeaders: ['Authorization'],
  });
  logger.log(`🌍 CORS configurado para origens: ${allowedOrigins.join(', ')}`);

  // Inicia o servidor HTTP
  const port = configService.get('PORT') || 3000;
  await app.listen(port);

  logger.log(`🚀 Aplicação rodando em: ${await app.getUrl()}`);
  logger.log(`🏁 Ambiente: ${configService.get('NODE_ENV') || 'development'}`);
}

bootstrap().catch((error) => {
  const logger = new Logger('Bootstrap');
  logger.error(`💥 Falha ao iniciar a aplicação: ${error.message}`);
  process.exit(1);
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
