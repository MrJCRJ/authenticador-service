// src/auth/auth.service.ts
import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as Joi from 'joi';

interface UserBase {
  id?: string;
  sub?: string;
  email: string;
  name: string;
  picture?: string;
  locale?: string;
  verified?: boolean;
}

interface GoogleUser extends UserBase {
  accessToken: string;
  refreshToken?: string;
}

interface JwtPayload extends UserBase {
  iat?: number;
  exp?: number;
  googleAccessToken?: string; // Adicione esta linha
  googleRefreshToken?: string; // Opcional, se quiser incluir
}

interface RefreshTokenPayload extends UserBase {
  type: 'refresh';
  iat?: number;
  exp?: number;
}

interface TokenUser {
  sub: string;
  email: string;
  name: string;
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly payloadSchema = Joi.object({
    sub: Joi.string().required(),
    email: Joi.string().email().required(),
    name: Joi.string().required(),
    picture: Joi.string().uri().optional(),
    locale: Joi.string().optional(),
    verified: Joi.boolean().optional(),
    googleAccessToken: Joi.string().required(), // Adicione esta linha
    googleRefreshToken: Joi.string().optional(), // Opcional
    iat: Joi.number().optional(),
    exp: Joi.number().optional(),
  });

  private readonly refreshTokenSchema = Joi.object({
    sub: Joi.string().required(),
    email: Joi.string().email().required(),
    name: Joi.string().required(),
    type: Joi.string().valid('refresh').required(),
    iat: Joi.number().optional(),
    exp: Joi.number().optional(),
  });

  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  /**
   * Gera um token JWT seguro com informações do usuário
   * @param user Dados do usuário para inclusão no token
   * @returns Token JWT assinado
   */
  generateToken(user: GoogleUser): string {
    const payload: JwtPayload = {
      sub: user.id || user.sub || user.email,
      email: user.email,
      name: user.name,
      picture: user.picture,
      locale: user.locale,
      verified: user.verified,
      googleAccessToken: user.accessToken, // Inclui o access_token do Google
      googleRefreshToken: user.refreshToken, // Opcional - só inclua se for seguro
    };

    this.validatePayload(payload);

    this.logTokenActivity('Gerando token de acesso para', user.email);

    return this.jwtService.sign(payload, this.getAccessTokenOptions());
  }

  /**
   * Gera um refresh token para renovação de sessão
   * @param user Dados do usuário para inclusão no token
   * @returns Refresh token JWT assinado
   */
  generateRefreshToken(user: GoogleUser): string {
    const payload: RefreshTokenPayload = {
      sub: user.id || user.sub || user.email,
      email: user.email,
      name: user.name, // Garantindo que name está presente
      type: 'refresh',
    };

    const { error } = this.refreshTokenSchema.validate(payload);
    if (error) {
      this.logger.error(
        `❌ Payload de refresh token inválido: ${error.message}`,
      );
      throw new Error('Payload de refresh token inválido');
    }

    this.logTokenActivity('Gerando refresh token para', user.email);

    return this.jwtService.sign(payload, this.getRefreshTokenOptions());
  }

  /**
   * Validação completa do token JWT de acesso
   * @param token Token JWT a ser validado
   * @returns Dados do usuário contidos no token
   * @throws UnauthorizedException Se o token for inválido
   */
  async validateAccessToken(token: string): Promise<GoogleUser> {
    try {
      const payload = this.jwtService.verify<JwtPayload>(token, {
        secret: this.configService.getOrThrow<string>('JWT_SECRET'),
        issuer: this.configService.get<string>('JWT_ISSUER'),
        audience: this.configService.get<string>('JWT_AUDIENCE'),
        algorithms: ['HS256'],
      });

      this.validatePayload(payload);

      this.logTokenActivity('Token de acesso validado para', payload.email);

      return {
        id: payload.sub,
        email: payload.email,
        name: payload.name,
        picture: payload.picture,
        locale: payload.locale,
        verified: payload.verified,
        accessToken: payload.googleAccessToken || '', // Agora vem do payload
        refreshToken: payload.googleRefreshToken,
      };
    } catch (error) {
      this.logValidationError('Token de acesso', error);
      throw new UnauthorizedException('Token de acesso inválido ou expirado');
    }
  }

  /**
   * Validação completa do refresh token JWT
   * @param token Refresh token a ser validado
   * @returns Dados básicos do usuário contidos no token
   * @throws UnauthorizedException Se o token for inválido
   */
  async validateRefreshToken(
    token: string,
  ): Promise<{ sub: string; email: string; name: string }> {
    // Adicionado name no retorno
    try {
      const payload = this.jwtService.verify<RefreshTokenPayload>(token, {
        secret: this.configService.getOrThrow<string>('JWT_REFRESH_SECRET'),
        algorithms: ['HS256'],
      });

      const { error } = this.refreshTokenSchema.validate(payload);
      if (error || payload.type !== 'refresh') {
        throw new Error('Tipo de token inválido');
      }

      this.logTokenActivity('Refresh token validado para', payload.email);

      return {
        sub: payload.sub,
        email: payload.email,
        name: payload.name,
      };
    } catch (error) {
      this.logValidationError('Refresh token', error);
      throw new UnauthorizedException('Refresh token inválido ou expirado');
    }
  }

  /**
   * Renova tokens usando um refresh token válido
   * @param refreshToken Refresh token JWT
   * @returns Novo par de tokens (access e refresh)
   * @throws UnauthorizedException Se o refresh token for inválido
   */
  async refreshTokens(
    refreshToken: string,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const { sub, email, name } = await this.validateRefreshToken(refreshToken);

    const userData: GoogleUser = {
      sub,
      email,
      name,
      accessToken: '', // Será preenchido posteriormente
      picture: undefined,
      locale: undefined,
      verified: undefined,
    };

    const newAccessToken = this.generateToken(userData);
    const newRefreshToken = this.generateRefreshToken(userData);

    this.logger.log(`♻️ Tokens renovados para: ${this.obfuscateEmail(email)}`);

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    };
  }

  /**
   * Valida a estrutura do payload JWT
   * @param payload Dados do token a serem validados
   * @throws Error Se o payload for inválido
   */
  private validatePayload(payload: JwtPayload): void {
    const { error } = this.payloadSchema.validate(payload);
    if (error) {
      this.logger.error(`❌ Payload JWT inválido: ${error.message}`);
      throw new Error('Payload JWT inválido');
    }
  }

  /**
   * Decodificação segura para logs (não verifica assinatura)
   * @param token Token JWT a ser decodificado
   * @returns Payload decodificado ou null se inválido
   */
  decodeToken(token: string): JwtPayload | null {
    try {
      const payload = this.jwtService.decode(token) as JwtPayload;
      if (!payload) return null;

      return {
        ...payload,
        email: this.obfuscateEmail(payload.email),
      };
    } catch (error) {
      this.logger.error(
        `❌ Falha ao decodificar token: ${error instanceof Error ? error.message : 'Erro desconhecido'}`,
      );
      return null;
    }
  }

  private getAccessTokenOptions() {
    return {
      expiresIn: this.configService.get<string>('JWT_EXPIRES_IN', '1h'),
      secret: this.configService.getOrThrow<string>('JWT_SECRET'),
      issuer: this.configService.get<string>('JWT_ISSUER'),
      audience: this.configService.get<string>('JWT_AUDIENCE'),
    };
  }

  private getRefreshTokenOptions() {
    return {
      expiresIn: this.configService.get<string>('JWT_REFRESH_EXPIRES_IN', '7d'),
      secret: this.configService.getOrThrow<string>('JWT_REFRESH_SECRET'),
    };
  }

  private logTokenActivity(action: string, email: string) {
    this.logger.log(`${action}: ${this.obfuscateEmail(email)}`);
  }

  private logValidationError(tokenType: string, error: unknown) {
    this.logger.error(
      `❌ Falha na validação de ${tokenType}: ${error instanceof Error ? error.message : 'Erro desconhecido'}`,
      error instanceof Error ? error.stack : '',
    );
  }

  private obfuscateEmail(email: string): string {
    const [name, domain] = email.split('@');
    return `${name[0]}${'*'.repeat(Math.max(0, name.length - 1))}@${domain}`;
  }
}
