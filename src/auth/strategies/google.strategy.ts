// src/auth/strategies/google.strategy.ts
import { Injectable, Logger } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import {
  Strategy,
  VerifyCallback,
  StrategyOptionsWithRequest,
} from 'passport-google-oauth20';
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

interface GoogleUser {
  provider: string;
  providerId: string;
  email: string;
  name: string;
  picture: string | null;
  locale: string;
  accessToken: string;
  refreshToken: string;
}

interface AuthRequest extends Request {
  user?: GoogleUser;
  query: {
    state?: string;
    [key: string]: string | undefined;
  };
}

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  private readonly logger = new Logger(GoogleStrategy.name);

  constructor(configService: ConfigService) {
    const scopes = configService.get('GOOGLE_SCOPES')?.split(',') || [
      'email',
      'profile',
      'https://www.googleapis.com/auth/calendar.readonly',
    ];

    // Definindo a interface estendida para as opções
    interface ExtendedStrategyOptions extends StrategyOptionsWithRequest {
      accessType?: 'online' | 'offline';
      prompt?: 'none' | 'consent' | 'select_account';
    }

    const options: ExtendedStrategyOptions = {
      clientID: configService.getOrThrow('GOOGLE_CLIENT_ID'),
      clientSecret: configService.getOrThrow('GOOGLE_CLIENT_SECRET'),
      callbackURL: configService.getOrThrow('GOOGLE_CALLBACK_URL'),
      scope: scopes,
      passReqToCallback: true,
      accessType: 'offline', // Para obter refresh token
      prompt: 'consent', // Para forçar solicitação de permissões
    };

    super(options as StrategyOptionsWithRequest);

    this.logger.log(
      `📢 Escopos do Google carregados: ${JSON.stringify(scopes)}`,
    );
    this.logger.log(
      `🔗 URL de autenticação gerada: https://accounts.google.com/o/oauth2/auth?scope=${encodeURIComponent(
        scopes.join(' '),
      )}&access_type=offline&prompt=consent`,
    );
  }

  async validate(
    req: AuthRequest,
    accessToken: string,
    refreshToken: string,
    profile: GoogleProfile,
    done: VerifyCallback,
  ): Promise<void> {
    try {
      // 1️⃣ Validação do parâmetro state (CSRF protection)
      if (!req.query.state) {
        throw new Error('Parâmetro state é obrigatório para proteção CSRF');
      }

      // 2️⃣ Validação dos dados do perfil
      if (!profile.emails?.length) {
        throw new Error('Perfil do Google não contém informações de email');
      }

      const primaryEmail = profile.emails[0];
      if (!primaryEmail.verified) {
        throw new Error('Email do Google não verificado');
      }

      // 3️⃣ Construção do objeto do usuário com tipagem forte
      const user: GoogleUser = {
        provider: 'google',
        providerId: profile.id,
        email: primaryEmail.value,
        name:
          profile.displayName || profile.name?.givenName || 'Usuário Google',
        picture: profile.photos?.[0]?.value || null,
        locale: profile._json?.locale || 'pt-BR',
        accessToken,
        refreshToken,
      };

      // 4️⃣ Log estruturado
      this.logStructuredAuthInfo(user, req);

      // 5️⃣ Retorno do usuário autenticado
      done(null, user);
    } catch (error) {
      this.logger.error(
        `💥 Falha na autenticação com Google: ${error instanceof Error ? error.message : String(error)}`,
      );
      done(error instanceof Error ? error : new Error(String(error)), null);
    }
  }

  private logStructuredAuthInfo(user: GoogleUser, req: AuthRequest): void {
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
      metadata: {
        hasRefreshToken: !!user.refreshToken,
        locale: user.locale,
      },
    });
  }
}
