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

@Module({
  imports: [
    // ConfigModule para carregar variáveis de ambiente.
    ConfigModule.forRoot(),

    // PassportModule para configurar autenticação com Passport.
    // Define 'jwt' como a estratégia padrão.
    PassportModule.register({ defaultStrategy: 'jwt' }),

    // JwtModule para configurar a geração e validação de tokens JWT.
    // Usa registerAsync para carregar configurações dinamicamente.
    JwtModule.registerAsync({
      imports: [ConfigModule], // Depende do ConfigModule para acessar variáveis de ambiente.
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'), // Chave secreta para assinar tokens.
        signOptions: { expiresIn: '1h' }, // Tempo de expiração do token (1 hora).
      }),
      inject: [ConfigService], // Injeta o ConfigService para uso no useFactory.
    }),
  ],
  controllers: [AuthController], // Controladores do módulo.
  providers: [
    AuthService, // Serviço para lógica de autenticação.
    GoogleStrategy, // Estratégia de autenticação via Google OAuth2.
    JwtStrategy, // Estratégia de autenticação via JWT.
    JwtGuard, // Guard para proteger rotas com JWT.
  ],
  exports: [
    AuthService, // Exporta o AuthService para uso em outros módulos.
    JwtGuard, // Exporta o JwtGuard para uso em outros módulos.
  ],
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
