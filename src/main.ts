// src/main.ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import { Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { ValidationPipe } from '@nestjs/common';
import * as helmet from 'helmet';
import * as rateLimit from 'express-rate-limit';
import {
  makeCounterProvider,
  PrometheusModule,
} from '@willsoto/nestjs-prometheus';
import { Registry } from 'prom-client';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);
  const logger = new Logger('Bootstrap');

  // Configuração de logs estruturados
  const logContext = {
    environment: configService.get('NODE_ENV') || 'development',
    timestamp: new Date().toISOString(),
  };

  // Configuração do Prometheus (se habilitado)
  if (configService.get('PROMETHEUS_ENABLED') === 'true') {
    const registry = new Registry();
    registry.setDefaultLabels({
      app: 'authenticator-service',
    });

    // Habilita métricas padrão
    const collectDefaultMetrics = require('prom-client').collectDefaultMetrics;
    collectDefaultMetrics({
      register: registry,
      timeout: 5000,
    });

    logger.log({
      message: '📊 Prometheus configurado e coletando métricas',
      ...logContext,
    });
  }

  // Middleware de segurança
  app.use(helmet.default());
  logger.log({
    message: '🔒 Middlewares de segurança configurados',
    ...logContext,
  });

  // Rate limiting
  app.use(
    rateLimit.default({
      windowMs: 15 * 60 * 1000, // 15 minutos
      max: configService.get<number>('RATE_LIMIT_MAX', 100),
      message: '⚠️ Muitas requisições deste IP, tente novamente mais tarde',
    }),
  );

  // Middleware para manipulação de cookies
  app.use(cookieParser());
  logger.log({
    message: '🍪 Cookie-parser configurado',
    ...logContext,
  });

  // Configuração do express-session
  app.use(
    session({
      secret: configService.getOrThrow<string>('SESSION_SECRET'),
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
  logger.log({
    message: '🔐 Express-session configurado',
    ...logContext,
  });

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
        logger.warn({
          message: '⚠️ Tentativa de acesso de origem não permitida',
          origin,
          ...logContext,
        });
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
  logger.log({
    message: '🌍 CORS configurado',
    allowedOrigins,
    ...logContext,
  });

  // Validação global
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  // Configuração do Swagger (apenas em desenvolvimento)
  if (configService.get('NODE_ENV') !== 'production') {
    const config = new DocumentBuilder()
      .setTitle('API Documentation')
      .setDescription('Documentação completa da API')
      .setVersion('1.0')
      .addBearerAuth()
      .build();
    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('api-docs', app, document);
    logger.log({
      message: '📚 Swagger configurado em /api-docs',
      ...logContext,
    });
  }

  // Inicia o servidor HTTP
  const port = configService.get<number>('PORT', 3000);
  await app.listen(port);

  logger.log({
    message: '🚀 Aplicação iniciada com sucesso',
    url: await app.getUrl(),
    port,
    ...logContext,
  });
}

bootstrap().catch((error) => {
  const logger = new Logger('Bootstrap');
  logger.error({
    message: '💥 Falha ao iniciar a aplicação',
    error: error.message,
    stack: error.stack,
    timestamp: new Date().toISOString(),
  });
  process.exit(1);
});
