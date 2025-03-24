// src/auth/auth.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { GoogleStrategy } from './strategies/google.strategy';
import { JwtStrategy } from './strategies/jwt.strategy';
import { JwtGuard } from './guards/jwt.guard';
import * as Joi from 'joi';

@Module({
  imports: [
    ConfigModule.forRoot({
      validationSchema: Joi.object({
        JWT_SECRET: Joi.string().required(),
        JWT_EXPIRES_IN: Joi.string().default('1h'),
        JWT_ISSUER: Joi.string().default('my-app'),
        GOOGLE_CLIENT_ID: Joi.string().required(),
        GOOGLE_CLIENT_SECRET: Joi.string().required(),
        GOOGLE_CALLBACK_URL: Joi.string().required(),
        COOKIE_DOMAIN: Joi.string().optional(),
      }),
    }),

    PassportModule.register({
      defaultStrategy: 'jwt',
      session: false, // Desativado para APIs stateless
      property: 'user', // Onde os dados do usuário serão armazenados
    }),

    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: {
          expiresIn: configService.get<string>('JWT_EXPIRES_IN'),
          issuer: configService.get<string>('JWT_ISSUER'),
          algorithm: 'HS256', // Algoritmo recomendado
        },
        verifyOptions: {
          algorithms: ['HS256'],
          issuer: configService.get<string>('JWT_ISSUER'),
        },
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    GoogleStrategy,
    JwtStrategy,
    JwtGuard,
    // Configuração adicional para serialização
    {
      provide: 'JWT_CONFIG',
      useFactory: (configService: ConfigService) => ({
        cookieName: 'jwt',
        domain: configService.get('COOKIE_DOMAIN'),
      }),
      inject: [ConfigService],
    },
  ],
  exports: [AuthService, JwtGuard, JwtModule],
})
export class AuthModule {}

/**Sugestões de Melhoria (Para Implementar):
Configuração de Refresh Token:

Adicione suporte para refresh tokens no JwtModule.

typescript
Copy
useFactory: async (configService: ConfigService) => ({
  secret: configService.get<string>('JWT_SECRET'),
  signOptions: {
    expiresIn: configService.get<string>('JWT_EXPIRES_IN', '1h'), // Expiração do access token.
  },
  refreshTokenSecret: configService.get<string>('JWT_REFRESH_SECRET'),
  refreshTokenExpiresIn: configService.get<string>('JWT_REFRESH_EXPIRES_IN', '7d'), // Expiração do refresh token.
}),
Suporte a Múltiplas Estratégias:

Adicione outras estratégias de autenticação (por exemplo, Facebook, GitHub).

typescript
Copy
providers: [
  AuthService,
  GoogleStrategy,
  FacebookStrategy, // Nova estratégia.
  JwtStrategy,
  JwtGuard,
],
Configuração de Cookies:

Adicione configurações globais para cookies no módulo.

typescript
Copy
imports: [
  ConfigModule.forRoot(),
  PassportModule.register({ defaultStrategy: 'jwt' }),
  JwtModule.registerAsync({ ... }),
  CookieModule.forRoot({ // Configurações globais de cookies.
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
  }),
],
Testes Automatizados:

Adicione testes automatizados para garantir que o módulo funcione corretamente.

typescript
Copy
// Exemplo de teste:
describe('AuthModule', () => {
  it('deve carregar o módulo corretamente', () => {
    const module = new AuthModule();
    expect(module).toBeDefined();
  });
});
Documentação:

Adicione uma documentação clara usando JSDoc para explicar o propósito do módulo e como ele deve ser usado.

typescript
Copy
/**
 * Módulo de autenticação.
 * Configura estratégias de autenticação (Google, JWT) e protege rotas com guards.

@Module({ ... })
export class AuthModule {}
Segurança:

Adicione validações adicionais para garantir que as variáveis de ambiente necessárias estejam definidas.

typescript
Copy
useFactory: async (configService: ConfigService) => {
  const jwtSecret = configService.get<string>('JWT_SECRET');
  if (!jwtSecret) {
    throw new Error('JWT_SECRET não está definido no ambiente.');
  }
  return {
    secret: jwtSecret,
    signOptions: { expiresIn: '1h' },
  };
},
 
 */
