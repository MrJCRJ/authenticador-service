// src/app.controller.ts
import { Controller, Get, Logger, Res, Req, UseGuards } from '@nestjs/common';
import { Response, Request } from 'express';
import { ConfigService } from '@nestjs/config';
import { Throttle, ThrottlerGuard } from '@nestjs/throttler';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';

@ApiTags('App')
@Controller()
export class AppController {
  private readonly logger = new Logger(AppController.name);

  constructor(private readonly configService: ConfigService) {}

  /**
   * Rota raiz da aplicação com informações básicas
   */
  @Get()
  @ApiOperation({ summary: 'Obter informações básicas da aplicação' })
  @ApiResponse({ status: 200, description: 'Informações da aplicação' })
  @ApiResponse({ status: 500, description: 'Erro interno do servidor' })
  @UseGuards(ThrottlerGuard)
  @Throttle({ default: { limit: 100, ttl: 60 } }) // 100 requisições por minuto
  getAppInfo(@Req() req: Request, @Res() res: Response) {
    try {
      this.logger.log('🌍 Requisição GET recebida na rota raiz');

      const appInfo = {
        status: 'online',
        environment: this.configService.get('NODE_ENV'),
        version: this.configService.get('APP_VERSION', '1.0.0'),
        session: req.session?.id ? 'active' : 'inactive',
        authEndpoints: {
          google: '/auth/google/init',
          profile: '/auth/profile',
          logout: '/auth/logout',
          refresh: '/auth/refresh',
        },
        docs: '/api-docs',
        uptime: process.uptime(),
      };

      this.logger.debug(`Informações da sessão: ${req.session?.id}`);
      this.logger.debug(`IP do cliente: ${req.ip}`);

      return res.json(appInfo);
    } catch (error) {
      this.logger.error(`💥 Erro na rota raiz: ${error}`);
      return res.status(500).json({
        error: 'Erro interno do servidor',
        message:
          this.configService.get('NODE_ENV') === 'development'
            ? error
            : undefined,
      });
    }
  }

  /**
   * Rota de health check para monitoramento
   */
  @Get('health')
  @ApiOperation({ summary: 'Verificar saúde da aplicação' })
  @ApiResponse({ status: 200, description: 'Aplicação saudável' })
  @Throttle({ default: { limit: 10, ttl: 60 } }) // 10 requisições por minuto
  getHealthCheck() {
    this.logger.log('🩺 Health check executado');
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      database: 'connected', // Adicione verificações reais de conexão
      memoryUsage: process.memoryUsage().rss,
    };
  }

  /**
   * Rota de informações de configuração (apenas em desenvolvimento)
   */
  @Get('config')
  @ApiOperation({ summary: 'Obter configurações (apenas desenvolvimento)' })
  @ApiResponse({ status: 200, description: 'Configurações seguras' })
  @ApiResponse({ status: 403, description: 'Acesso negado em produção' })
  getConfig(@Res() res: Response) {
    try {
      if (this.configService.get('NODE_ENV') !== 'development') {
        this.logger.warn(
          '⚠️ Tentativa de acesso ao endpoint de configuração em ambiente não-desenvolvimento',
        );
        return res.status(403).json({
          error: 'Acesso negado',
          message:
            'Este endpoint está disponível apenas em ambiente de desenvolvimento',
        });
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
        features: {
          throttling:
            this.configService.get('THROTTLE_ENABLED', 'true') === 'true',
          swagger: this.configService.get('SWAGGER_ENABLED', 'true') === 'true',
        },
      };

      return res.json(safeConfig);
    } catch (error) {
      this.logger.error(`💥 Erro no endpoint de configuração: ${error}`);
      return res.status(500).json({
        error: 'Erro ao obter configurações',
        details:
          this.configService.get('NODE_ENV') === 'development'
            ? error
            : undefined,
      });
    }
  }

  /**
   * Rota de status do sistema
   */
  @Get('status')
  @ApiOperation({ summary: 'Obter status detalhado do sistema' })
  @ApiResponse({ status: 200, description: 'Status do sistema' })
  @Throttle({ default: { limit: 30, ttl: 60 } }) // 30 requisições por minuto
  getSystemStatus() {
    this.logger.log('📊 Verificando status do sistema...');
    return {
      status: 'operational',
      timestamp: new Date().toISOString(),
      resources: {
        cpu: process.cpuUsage(),
        memory: process.memoryUsage(),
      },
      dependencies: {
        database: 'ok', // Substituir por verificação real
        cache: 'ok', // Substituir por verificação real
      },
    };
  }
}
