// src/app.module.ts

import { Module, Logger } from '@nestjs/common';
import { AppController } from './app.controller';
import { AuthModule } from './auth/auth.module';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { PassportModule } from '@nestjs/passport';
import * as Joi from 'joi'; // Para validação de variáveis de ambiente

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: `.env.${process.env.NODE_ENV || 'development'}`,
      validationSchema: Joi.object({
        NODE_ENV: Joi.string()
          .valid('development', 'production', 'test')
          .default('development'),
        PORT: Joi.number().default(3000),
        SESSION_SECRET: Joi.string().required(),
        GOOGLE_CLIENT_ID: Joi.string().required(),
        GOOGLE_CLIENT_SECRET: Joi.string().required(),
        FRONTEND_URLS: Joi.string().required(),
        JWT_SECRET: Joi.string().required(),
      }),
      validationOptions: {
        allowUnknown: true,
        abortEarly: true,
      },
    }),

    // Configuração global do Passport
    PassportModule.register({
      defaultStrategy: 'google',
      session: true,
    }),

    AuthModule,
  ],
  controllers: [AppController],
  providers: [],
})
export class AppModule {
  private readonly logger = new Logger(AppModule.name);

  constructor(private readonly configService: ConfigService) {
    this.logConfiguration();
  }

  private logConfiguration() {
    this.logger.log('🚀 Módulo principal da aplicação carregado com sucesso!');
    this.logger.log(`🏷️ Ambiente: ${this.configService.get('NODE_ENV')}`);
    this.logger.log(
      `🌍 Frontend URLs: ${this.configService.get('FRONTEND_URLS')}`,
    );

    // Log seguro (não mostra valores sensíveis)
    this.logger.log('🔑 Configuração do Google OAuth:');
    this.logger.log(
      `- Client ID: ${this.configService.get('GOOGLE_CLIENT_ID') ? '✔️ Configurado' : '❌ Ausente'}`,
    );
    this.logger.log(
      `- Client Secret: ${this.configService.get('GOOGLE_CLIENT_SECRET') ? '✔️ Configurado' : '❌ Ausente'}`,
    );
  }
}

/**Sugestões de Melhoria (Para Implementar):
Suporte a Múltiplos Ambientes:

Adicione suporte para diferentes arquivos .env com base no ambiente.

typescript
Copy
envFilePath: `.env.${process.env.NODE_ENV || 'development'}`,
Módulos Adicionais:

Adicione outros módulos conforme necessário (por exemplo, UsersModule, DatabaseModule).

typescript
Copy
imports: [ConfigModule.forRoot({ isGlobal: true }), AuthModule, UsersModule],
Documentação com Swagger:

Adicione o SwaggerModule para documentar a API.

typescript
Copy
import { SwaggerModule } from '@nestjs/swagger';

@Module({
  imports: [ConfigModule.forRoot({ isGlobal: true }), AuthModule, SwaggerModule],
})
Tratamento de Erros Global:

Adicione um filtro de exceções global para capturar e tratar erros.

typescript
Copy
import { APP_FILTER } from '@nestjs/core';
import { HttpExceptionFilter } from './common/filters/http-exception.filter';

@Module({
  providers: [
    {
      provide: APP_FILTER,
      useClass: HttpExceptionFilter,
    },
  ],
})
Testes Automatizados:

Adicione testes de integração para garantir que o módulo funcione corretamente.

typescript
Copy
describe('AppModule', () => {
  it('deve carregar o módulo corretamente', () => {
    const module = new AppModule();
    expect(module).toBeDefined();
  });
});
Segurança:

Adicione proteção contra ataques comuns (por exemplo, CORS, rate limiting).

typescript
Copy
import { ThrottlerModule } from '@nestjs/throttler';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    ThrottlerModule.forRoot({ ttl: 60, limit: 10 }), // Limita a 10 requisições por minuto.
    AuthModule,
  ],
})
Monitoramento:

Adicione suporte para ferramentas de monitoramento (por exemplo, Prometheus, New Relic).

typescript
Copy
import { PrometheusModule } from '@willsoto/nestjs-prometheus';

@Module({
  imports: [ConfigModule.forRoot({ isGlobal: true }), AuthModule, PrometheusModule],
})
Exemplo de Saída de Logs:
Copy
🚀 Módulo principal da aplicação carregado com sucesso! */
