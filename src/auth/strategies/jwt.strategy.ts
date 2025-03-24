// src/auth/strategies/jwt.strategy.ts
import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy, StrategyOptions } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { Algorithm } from 'jsonwebtoken';

/**
 * Interface para tipagem do payload JWT
 */
interface JwtPayload {
  sub: string; // ID do usuário (subject)
  email: string; // Email do usuário
  name?: string; // Nome do usuário (opcional)
  picture?: string; // URL da foto do usuário (opcional)
  iat?: number; // Timestamp de quando o token foi emitido
  exp?: number; // Timestamp de quando o token expira
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  private readonly logger = new Logger(JwtStrategy.name);

  constructor(configService: ConfigService) {
    const options: StrategyOptions = {
      jwtFromRequest: ExtractJwt.fromExtractors([
        ExtractJwt.fromAuthHeaderAsBearerToken(),
        ExtractJwt.fromUrlQueryParameter('token'),
        (req) => req?.cookies?.jwt,
      ]),
      ignoreExpiration: configService.get<boolean>(
        'JWT_IGNORE_EXPIRATION',
        false,
      ),
      secretOrKey: configService.getOrThrow<string>('JWT_SECRET'),
      audience: configService.get<string>('JWT_AUDIENCE'),
      issuer: configService.get<string>('JWT_ISSUER'),
      algorithms: ['HS256'] as Algorithm[], // Tipo corrigido
    };

    super(options);

    this.logger.log({
      message: '🔐 Estratégia JWT configurada com sucesso',
      config: {
        issuer: options.issuer,
        audience: options.audience,
        algorithm: options.algorithms?.[0],
      },
    });
  }

  /**
   * Valida o payload do token JWT
   * @param payload Dados decodificados do token JWT
   * @returns Objeto com informações do usuário autenticado
   * @throws UnauthorizedException Se o payload for inválido
   */
  async validate(payload: JwtPayload): Promise<any> {
    try {
      this.validatePayload(payload);
      this.logStructuredPayload(payload);

      return {
        userId: payload.sub,
        email: payload.email,
        ...(payload.name && { name: payload.name }),
        ...(payload.picture && { picture: payload.picture }),
      };
    } catch (error) {
      const errorMessage =
        error instanceof Error
          ? error.message
          : 'Erro desconhecido na validação do token';

      this.logger.error({
        message: '💥 Falha na validação do token JWT',
        error: errorMessage,
        payload: this.sanitizePayloadForLogging(payload),
      });
      throw new UnauthorizedException(errorMessage);
    }
  }

  /**
   * Valida os campos obrigatórios do payload JWT
   * @param payload Dados decodificados do token
   * @throws Error Se algum campo obrigatório estiver faltando
   */
  private validatePayload(payload: JwtPayload): void {
    const requiredFields = ['sub', 'email'];
    const missingFields = requiredFields.filter((field) => !payload[field]);

    if (missingFields.length > 0) {
      throw new Error(
        `Payload JWT inválido: campos obrigatórios faltando (${missingFields.join(', ')})`,
      );
    }

    if (!this.isValidEmail(payload.email)) {
      throw new Error('Email no payload JWT não é válido');
    }
  }

  /**
   * Verifica se um email tem formato válido
   * @param email Email a ser validado
   * @returns boolean indicando se o email é válido
   */
  private isValidEmail(email: string): boolean {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  /**
   * Registra informações estruturadas sobre o payload
   * @param payload Dados decodificados do token
   */
  private logStructuredPayload(payload: JwtPayload): void {
    this.logger.log({
      message: '📄 Payload JWT validado com sucesso',
      user: {
        id: payload.sub,
        email: this.obfuscateEmail(payload.email),
        ...(payload.name && { name: payload.name }),
      },
      tokenInfo: {
        issuedAt: payload.iat
          ? new Date(payload.iat * 1000).toISOString()
          : undefined,
        expiresAt: payload.exp
          ? new Date(payload.exp * 1000).toISOString()
          : undefined,
      },
    });
  }

  /**
   * Ofusca parte do email para logs (ex: j***@example.com)
   * @param email Email original
   * @returns Email ofuscado
   */
  private obfuscateEmail(email: string): string {
    const [name, domain] = email.split('@');
    return `${name[0]}***@${domain}`;
  }

  /**
   * Remove informações sensíveis do payload para logging
   * @param payload Payload original
   * @returns Payload sanitizado
   */
  private sanitizePayloadForLogging(payload: JwtPayload): Partial<JwtPayload> {
    const { sub, email, name, picture, iat, exp } = payload;
    return {
      sub,
      email: this.obfuscateEmail(email),
      ...(name && { name }),
      ...(picture && { picture: '***' }),
      iat,
      exp,
    };
  }
}

/**Próximas Melhorias Possíveis:
Blacklist de Tokens:

Verificação contra tokens revogados

Métricas:

Coleta de métricas de autenticação

Testes Automatizados:

Mock de tokens para testes unitários

Customização:

Hooks para validação customizada */
