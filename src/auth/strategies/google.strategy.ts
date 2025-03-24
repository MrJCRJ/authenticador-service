// src/auth/strategies/google.strategy.ts
import { Injectable, Logger } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';

interface GoogleProfile {
  id: string;
  emails: { value: string; verified: boolean }[];
  displayName?: string;
  name?: { givenName?: string; familyName?: string };
  photos?: { value: string }[];
  _json?: {
    locale?: string;
  };
}

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  private readonly logger = new Logger(GoogleStrategy.name);

  constructor(configService: ConfigService) {
    super({
      clientID: configService.getOrThrow('GOOGLE_CLIENT_ID'),
      clientSecret: configService.getOrThrow('GOOGLE_CLIENT_SECRET'),
      callbackURL: configService.getOrThrow('GOOGLE_CALLBACK_URL'),
      scope: configService.get('GOOGLE_SCOPES')?.split(',') || [
        'email',
        'profile',
      ],
      passReqToCallback: true,
    });
  }

  /**
   * Valida o perfil do usuário autenticado via Google OAuth
   * @param req Objeto de requisição HTTP
   * @param accessToken Token de acesso do Google
   * @param refreshToken Token de atualização do Google
   * @param profile Perfil do usuário retornado pelo Google
   * @param done Callback do Passport
   * @returns Objeto com dados do usuário ou erro
   */
  async validate(
    req: Request,
    accessToken: string,
    refreshToken: string,
    profile: GoogleProfile,
    done: VerifyCallback,
  ): Promise<any> {
    try {
      // 1️⃣ Validação do parâmetro state (para proteção CSRF)
      const state = req.query.state;
      if (!state) {
        throw new Error('Parâmetro state é obrigatório para proteção CSRF');
      }

      // 2️⃣ Validação dos dados do perfil
      if (!profile.emails || !profile.emails.length) {
        throw new Error('Perfil do Google não contém informações de email');
      }

      const primaryEmail = profile.emails[0];
      if (!primaryEmail.verified) {
        throw new Error('Email do Google não verificado');
      }

      // 3️⃣ Construção do objeto do usuário
      const user = {
        provider: 'google',
        providerId: profile.id,
        email: primaryEmail.value,
        name:
          profile.displayName || profile.name?.givenName || 'Usuário Google',
        picture: profile.photos?.[0]?.value || null,
        locale: profile._json?.locale || 'pt-BR',
        accessToken,
        refreshToken, // Incluído para possíveis renovações de token
      };

      // 4️⃣ Log estruturado
      this.logStructuredAuthInfo(user, req);

      // 5️⃣ Retorno do usuário autenticado
      done(null, user);
    } catch (error) {
      this.logger.error(`💥 Falha na autenticação com Google: ${error}`);
      done(error, null);
    }
  }

  /**
   * Registra informações estruturadas sobre a autenticação
   * @param user Dados do usuário autenticado
   * @param req Objeto de requisição HTTP
   */
  private logStructuredAuthInfo(user: any, req: Request): void {
    this.logger.log({
      message: 'Autenticação via Google realizada com sucesso',
      user: {
        id: user.providerId,
        email: user.email,
        name: user.name,
      },
      request: {
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        timestamp: new Date().toISOString(),
      },
    });
  }
}

/**Próximas Melhorias Possíveis:
Armazenamento de Refresh Token:

Implementar lógica para renovação automática de tokens

Testes Automatizados:

Mock do Passport e Google OAuth para testes

Métricas:

Integração com sistemas de monitoramento

Customização:

Permitir mapeamento customizado de campos do perfil */
