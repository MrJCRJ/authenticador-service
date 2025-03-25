// src/app.module.ts
import { Module, Logger } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { PassportModule } from '@nestjs/passport';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_FILTER, APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import * as Joi from 'joi';
import { PrometheusModule } from '@willsoto/nestjs-prometheus';
import { AppController } from './app.controller';
import { AuthModule } from './auth/auth.module';
import { HttpExceptionFilter } from './common/filters/http-exception.filter';
import { MetricsInterceptor } from './common/interceptors/metrics.interceptor';
import { PrometheusService } from './common/services/prometheus.service';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: `.env.${process.env.NODE_ENV || 'development'}`,
      validationSchema: Joi.object({
        NODE_ENV: Joi.string()
          .valid('development', 'production', 'test', 'staging')
          .default('development'),
        PORT: Joi.number().port().default(3000),
        SESSION_SECRET: Joi.string().required(),
        GOOGLE_CLIENT_ID: Joi.string().required(),
        GOOGLE_CLIENT_SECRET: Joi.string().required(),
        FRONTEND_URLS: Joi.string().required(),
        JWT_SECRET: Joi.string().required(),
        JWT_REFRESH_SECRET: Joi.string().required(),
        THROTTLE_TTL: Joi.number().default(60),
        THROTTLE_LIMIT: Joi.number().default(100),
        PROMETHEUS_ENABLED: Joi.boolean().default(false),
      }),
      validationOptions: {
        allowUnknown: true,
        abortEarly: false,
      },
    }),

    PrometheusModule.registerAsync({
      useFactory: (configService: ConfigService) => ({
        defaultMetrics: {
          enabled: configService.get('PROMETHEUS_ENABLED') === 'true',
        },
        path: '/metrics',
      }),
      inject: [ConfigService],
    }),

    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        throttlers: [
          {
            ttl: config.get<number>('THROTTLE_TTL') * 1000,
            limit: config.get<number>('THROTTLE_LIMIT'),
          },
        ],
      }),
    }),

    PassportModule.register({
      defaultStrategy: 'jwt',
      session: false,
    }),

    AuthModule,
  ],
  controllers: [AppController],
  providers: [
    {
      provide: APP_FILTER,
      useClass: HttpExceptionFilter,
    },
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: MetricsInterceptor,
    },
    PrometheusService,
  ],
  exports: [PrometheusService],
})
export class AppModule {
  private readonly logger = new Logger(AppModule.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly prometheusService: PrometheusService,
  ) {
    this.logConfiguration();
    this.validateEnvironment();
  }

  private logConfiguration() {
    this.logger.log('🚀 Módulo principal da aplicação carregado com sucesso!');
    this.logger.log(`🏷️ Ambiente: ${this.configService.get('NODE_ENV')}`);
    this.logger.log(`🌐 Porta: ${this.configService.get('PORT')}`);
    this.logger.log(
      `📊 Prometheus: ${this.configService.get('PROMETHEUS_ENABLED') ? '✔️ Habilitado' : '❌ Desabilitado'}`,
    );

    // Log seguro (não mostra valores sensíveis)
    this.logger.log('🔑 Configurações:');
    this.logger.log(
      `- Google OAuth: ${this.configService.get('GOOGLE_CLIENT_ID') ? '✔️ Configurado' : '❌ Ausente'}`,
    );
    this.logger.log(
      `- JWT: ${this.configService.get('JWT_SECRET') ? '✔️ Configurado' : '❌ Ausente'}`,
    );
  }

  private validateEnvironment() {
    if (this.configService.get('NODE_ENV') === 'production') {
      this.logger.warn(
        '⚠️ Ambiente de produção - verificando configurações críticas...',
      );

      const requiredInProd = [
        'SESSION_SECRET',
        'JWT_SECRET',
        'JWT_REFRESH_SECRET',
      ];
      const missing = requiredInProd.filter(
        (key) => !this.configService.get(key),
      );

      if (missing.length > 0) {
        this.logger.error(
          `❌ Configurações ausentes em produção: ${missing.join(', ')}`,
        );
        throw new Error(
          'Configurações críticas ausentes em ambiente de produção',
        );
      }
    }
  }
}
