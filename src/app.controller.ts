// src/app.controller.ts

import { Controller, Get, Logger, Res, Req } from '@nestjs/common';
import { Response, Request } from 'express';
import { ConfigService } from '@nestjs/config';

@Controller()
export class AppController {
  private readonly logger = new Logger(AppController.name);

  constructor(private readonly configService: ConfigService) {}

  /**
   * Rota raiz da aplicação - agora com mais informações
   */
  @Get()
  getAppInfo(@Req() req: Request, @Res() res: Response) {
    this.logger.log('🌍 Requisição GET recebida na rota raiz');

    const appInfo = {
      status: 'online',
      environment: this.configService.get('NODE_ENV'),
      version: '1.0.0',
      session: req.session?.id ? 'active' : 'inactive',
      authEndpoints: {
        google: '/auth/google/init',
        profile: '/auth/profile',
        logout: '/auth/logout',
      },
      docs: '/api-docs', // Se tiver Swagger/OpenAPI
    };

    // Log adicional para debugging
    this.logger.debug(`Informações da sessão: ${JSON.stringify(req.session)}`);
    this.logger.debug(`Headers: ${JSON.stringify(req.headers)}`);

    return res.json(appInfo);
  }

  /**
   * Rota de health check para monitoramento
   */
  @Get('health')
  getHealthCheck() {
    this.logger.log('🩺 Health check executado');
    return { status: 'ok', timestamp: new Date().toISOString() };
  }

  /**
   * Rota de informações de configuração (apenas em desenvolvimento)
   */
  @Get('config')
  getConfig(@Res() res: Response) {
    if (this.configService.get('NODE_ENV') !== 'development') {
      return res.status(403).json({ error: 'Acesso negado' });
    }

    this.logger.warn(
      '⚠️ Acesso ao endpoint de configuração em desenvolvimento',
    );

    const safeConfig = {
      env: this.configService.get('NODE_ENV'),
      port: this.configService.get('PORT'),
      frontendUrls: this.configService.get('FRONTEND_URLS'),
      googleAuthConfigured: !!this.configService.get('GOOGLE_CLIENT_ID'),
      sessionSecretConfigured: !!this.configService.get('SESSION_SECRET'),
      jwtConfigured: !!this.configService.get('JWT_SECRET'),
    };

    return res.json(safeConfig);
  }
}

/**Sugestões de Melhoria (Para Implementar):
Rota de Status da Aplicação:

Adicione uma rota para verificar o status da aplicação (health check).

typescript
Copy
@Get('status')
getStatus(): { status: string } {
  this.logger.log('🩺 Verificando status da aplicação...');
  return { status: 'up' };
}
Documentação com Swagger:

Adicione anotações do Swagger para documentar a API.

typescript
Copy
import { ApiOperation, ApiResponse } from '@nestjs/swagger';

@Get()
@ApiOperation({ summary: 'Retorna uma mensagem de boas-vindas' })
@ApiResponse({ status: 200, description: 'Mensagem de boas-vindas' })
getHello(): string {
  return 'Hello World!';
}
Tratamento de Erros:

Adicione um bloco try-catch para capturar e tratar possíveis erros.

typescript
Copy
@Get()
getHello(): string {
  try {
    this.logger.log('🌍 Requisição GET recebida na rota raiz.');
    return 'Hello World!';
  } catch (error) {
    this.logger.error(`💥 Erro ao processar requisição: ${error.message}`);
    throw error;
  }
}
Configuração Dinâmica:

Use o ConfigService para carregar mensagens dinamicamente.

typescript
Copy
constructor(private readonly configService: ConfigService) {}

@Get()
getHello(): string {
  return this.configService.get<string>('WELCOME_MESSAGE', 'Hello World!');
}
Testes Automatizados:

Adicione testes unitários para garantir que o controlador funcione corretamente.

typescript
Copy
describe('AppController', () => {
  let appController: AppController;

  beforeEach(() => {
    appController = new AppController();
  });

  it('deve retornar "Hello World!"', () => {
    expect(appController.getHello()).toBe('Hello World!');
  });
});
Segurança:

Adicione proteção contra ataques comuns (por exemplo, rate limiting).

typescript
Copy
import { Throttle } from '@nestjs/throttler';

@Throttle({ default: { limit: 10, ttl: 60 } }) // Limita a 10 requisições por minuto.
@Get()
getHello(): string {
  return 'Hello World!';
}
Exemplo de Saída de Logs:
Copy
🌍 Requisição GET recebida na rota raiz. */
