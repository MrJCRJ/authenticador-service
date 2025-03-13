// /src/auth/auth.module.ts

// Importa o decorador `Module` do pacote @nestjs/common, que é usado para definir um módulo no NestJS.
import { Module } from '@nestjs/common';

// Importa o ConfigModule do pacote @nestjs/config para carregar variáveis de ambiente e configurações.
import { ConfigModule } from '@nestjs/config';

// Importa o PassportModule do pacote @nestjs/passport para integrar o Passport.js, uma biblioteca de autenticação.
import { PassportModule } from '@nestjs/passport';

// Importa o AuthService, que contém a lógica de negócio relacionada à autenticação.
import { AuthService } from './auth.service';

// Importa o AuthController, que lida com as rotas relacionadas à autenticação.
import { AuthController } from './auth.controller';

// Importa a estratégia do Google para autenticação OAuth2.
import { GoogleStrategy } from './strategies/google.strategy';

// Define o módulo de autenticação usando o decorador @Module.
@Module({
  // Lista de módulos importados.
  imports: [
    // ConfigModule.forRoot() carrega as variáveis de ambiente do arquivo .env ou do ambiente de execução.
    ConfigModule.forRoot(),

    // PassportModule.register() configura o Passport.js para usar sessões (session: true).
    // Isso é útil para autenticação baseada em sessão, como OAuth2.
    PassportModule.register({ session: true }),
  ],

  // Lista de provedores (services, estratégias, etc.) que pertencem a este módulo.
  providers: [
    // AuthService contém a lógica de negócio para autenticação.
    AuthService,

    // GoogleStrategy é a estratégia de autenticação do Google OAuth2.
    GoogleStrategy,
  ],

  // Lista de controladores que pertencem a este módulo.
  controllers: [
    // AuthController lida com as rotas relacionadas à autenticação.
    AuthController,
  ],
})
// Exporta a classe AuthModule, que representa o módulo de autenticação da aplicação.
export class AuthModule {}
