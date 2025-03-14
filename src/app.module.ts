// src/app.module.ts

// Importa o decorador `Module` do pacote @nestjs/common, que é usado para definir um módulo no NestJS.
import { Module, Logger } from '@nestjs/common';

// Importa o controlador principal da aplicação.
import { AppController } from './app.controller';

// Importa o módulo de autenticação, que contém controladores, provedores e outros componentes relacionados à autenticação.
import { AuthModule } from './auth/auth.module';

// Importa o ConfigModule para carregar variáveis de ambiente.
import { ConfigModule } from '@nestjs/config';

// Define o módulo principal da aplicação usando o decorador @Module.
@Module({
  // A lista de módulos importados.
  imports: [
    // ConfigModule para carregar variáveis de ambiente de forma global.
    ConfigModule.forRoot({
      isGlobal: true, // Torna as variáveis de ambiente disponíveis em toda a aplicação.
      envFilePath: `.env.${process.env.NODE_ENV || 'development'}`, // Carrega o arquivo .env correspondente ao ambiente.
    }),

    // AuthModule para funcionalidades de autenticação e autorização.
    AuthModule,
  ],

  // A lista de controladores que pertencem a este módulo.
  controllers: [AppController],

  // A lista de provedores (services, repositories, etc.) que pertencem a este módulo.
  providers: [],
})
// Exporta a classe AppModule, que representa o módulo principal da aplicação.
export class AppModule {
  // Logger personalizado para o AppModule, com emojis para logs divertidos e intuitivos 🎉
  private readonly logger = new Logger(AppModule.name);

  constructor() {
    // Log intuitivo: confirma que o módulo foi carregado com sucesso.
    this.logger.log('🚀 Módulo principal da aplicação carregado com sucesso!');
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
