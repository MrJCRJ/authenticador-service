// src/auth/auth.controller.ts
import {
  Controller,
  Get,
  Req,
  UseGuards,
  Res,
  Post,
  UnauthorizedException,
  UseFilters,
  Body,
  Header,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { JwtGuard } from './guards/jwt.guard';
import { AuthService } from './auth.service';
import { Logger } from '@nestjs/common';
import { Response, Request } from 'express';
import axios, { AxiosError } from 'axios';
import * as jwt from 'jsonwebtoken';
import { ConfigService } from '@nestjs/config';
import { CookieOptions } from 'express';
import { Throttle } from '@nestjs/throttler';
import { AuthExceptionFilter } from './filters/auth-exception.filter';

interface GoogleAuthRequest extends Request {
  query: {
    state?: string;
    code?: string;
    error?: string;
    redirect?: string;
    message?: string;
  };
}

interface GoogleUser {
  accessToken: string;
  refreshToken?: string;
  email: string;
  name: string;
  picture?: string;
  id?: string;
  locale?: string;
  verified?: boolean;
}

declare module 'express-session' {
  interface SessionData {
    frontendOrigin?: string;
    user?: GoogleUser;
  }
}

@Controller('auth')
@UseFilters(AuthExceptionFilter)
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
  ) {}

  private getCookieOptions(): CookieOptions {
    return {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      sameSite:
        this.configService.get('NODE_ENV') === 'production' ? 'none' : 'lax',
      maxAge: 3600000,
      path: '/',
      domain: this.configService.get('COOKIE_DOMAIN') || undefined,
    };
  }

  private isValidUrl(url: string): boolean {
    try {
      const parsedUrl = new URL(url);
      const allowedOrigins =
        this.configService.get('ALLOWED_ORIGINS')?.split(',') || [];
      return (
        ['http:', 'https:'].includes(parsedUrl.protocol) &&
        (allowedOrigins.includes('*') ||
          allowedOrigins.includes(parsedUrl.origin))
      );
    } catch {
      return false;
    }
  }

  @Get('favicon.ico')
  @Header('Content-Type', 'image/x-icon')
  returnFavicon() {
    return null; // Ou sirva um favicon real se tiver
  }

  @Get('error')
  authError(@Req() req: GoogleAuthRequest, @Res() res: Response) {
    const message =
      typeof req.query.message === 'string'
        ? req.query.message
        : 'unknown_error';
    this.logger.error(`❌ Erro de autenticação: ${message}`);

    return res.status(401).json({
      error: 'Authentication Error',
      message: this.getErrorMessage(message),
    });
  }

  private getErrorMessage(code: string): string {
    const messages: Record<string, string> = {
      redirect_missing: 'URL de redirecionamento não fornecida',
      auth_failed: 'Falha na autenticação com Google',
      invalid_state: 'Parâmetro state inválido',
      invalid_user: 'Usuário não autorizado',
      rate_limit: 'Muitas requisições. Tente novamente mais tarde.',
      default: 'Erro desconhecido durante a autenticação',
    };

    return messages[code] || messages.default;
  }

  @Get('google/init')
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  async googleAuthInit(@Req() req: GoogleAuthRequest, @Res() res: Response) {
    const redirectUrl =
      typeof req.query.redirect === 'string' ? req.query.redirect : null;

    if (!redirectUrl || !this.isValidUrl(redirectUrl)) {
      this.logger.error('⚠️ URL de redirecionamento inválida ou não fornecida');
      return res.redirect('/auth/error?message=redirect_missing');
    }

    const state = Buffer.from(redirectUrl).toString('base64');
    req.session.frontendOrigin = redirectUrl;

    const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    authUrl.searchParams.append(
      'client_id',
      this.configService.getOrThrow('GOOGLE_CLIENT_ID'),
    );
    authUrl.searchParams.append(
      'redirect_uri',
      this.configService.getOrThrow('GOOGLE_CALLBACK_URL'),
    );
    authUrl.searchParams.append('response_type', 'code');
    authUrl.searchParams.append('scope', 'email profile');
    authUrl.searchParams.append('state', state);
    authUrl.searchParams.append('access_type', 'offline');
    authUrl.searchParams.append('prompt', 'consent');

    this.logger.log(`🔗 Iniciando autenticação para: ${redirectUrl}`);
    return res.redirect(authUrl.toString());
  }

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleAuthRedirect(
    @Req() req: GoogleAuthRequest,
    @Res() res: Response,
  ) {
    try {
      if (!req.query.state || typeof req.query.state !== 'string') {
        throw new Error('Parâmetro state inválido ou ausente');
      }

      const frontendOrigin = Buffer.from(req.query.state, 'base64').toString(
        'utf-8',
      );
      if (!this.isValidUrl(frontendOrigin)) {
        throw new Error('URL de redirecionamento inválida');
      }

      const user = req.user as GoogleUser | undefined;
      if (!user?.accessToken || !this.validateUser(user)) {
        throw new UnauthorizedException('Usuário não autorizado');
      }

      // Gera token de acesso incluindo os tokens do Google
      const token = this.authService.generateToken({
        ...user,
        accessToken: user.accessToken, // Garante que está incluído
        refreshToken: user.refreshToken, // Opcional
      });

      // Configura cookies
      const cookieOptions = this.getCookieOptions();
      res.cookie('jwt', token, cookieOptions);

      // Redireciona com token e dados do usuário
      const redirectUrl = new URL(frontendOrigin);
      redirectUrl.searchParams.append('token', token);
      redirectUrl.searchParams.append(
        'user',
        JSON.stringify({
          email: user.email,
          name: user.name,
          picture: user.picture,
        }),
      );

      this.logger.log(
        `✅ Autenticação bem-sucedida para: ${this.obfuscateEmail(user.email)}`,
      );
      return res.redirect(redirectUrl.toString());
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : 'Erro desconhecido';
      this.logger.error(`❌ Erro no callback: ${errorMessage}`);
      return res.redirect('/auth/error?message=auth_failed');
    }
  }

  private validateUser(user: GoogleUser): boolean {
    // Implemente sua lógica de validação de usuário aqui
    // Por exemplo, verificar se o email está em uma lista de domínios permitidos
    return !!user.email;
  }

  private obfuscateEmail(email: string): string {
    const [name, domain] = email.split('@');
    return `${name[0]}${'*'.repeat(Math.max(0, name.length - 1))}@${domain}`;
  }

  @Post('logout')
  async logout(@Req() req: Request, @Res() res: Response) {
    this.logger.log('🔑 Iniciando logout...');

    // Tenta revogar o token do Google
    const googleAccessToken = this.extractGoogleToken(req);
    if (googleAccessToken) {
      await this.revokeGoogleToken(googleAccessToken);
    }

    // Limpa cookies e sessão
    this.clearAuthCookies(res);
    await this.destroySession(req);

    this.logger.log('👋 Logout realizado com sucesso');
    return res.status(200).json({ success: true });
  }

  private extractGoogleToken(req: Request): string | undefined {
    if (req.cookies.google_access_token) {
      return req.cookies.google_access_token;
    }

    try {
      const decoded = jwt.verify(
        req.cookies.jwt,
        this.configService.getOrThrow('JWT_SECRET'),
      ) as { accessToken?: string };
      return decoded.accessToken;
    } catch {
      this.logger.warn('⚠️ Não foi possível recuperar o token do JWT');
      return undefined;
    }
  }

  private async revokeGoogleToken(token: string): Promise<void> {
    try {
      await axios.post('https://oauth2.googleapis.com/revoke', null, {
        params: { token },
      });
      this.logger.log('🔑 Token do Google revogado com sucesso!');
    } catch (error) {
      const errorMessage =
        error instanceof AxiosError
          ? error.response?.data?.error || error.message
          : 'Erro desconhecido';
      this.logger.error('❌ Erro ao revogar token:', errorMessage);
    }
  }

  private clearAuthCookies(res: Response): void {
    const cookieOptions = this.getCookieOptions();
    res.clearCookie('jwt', cookieOptions);
    res.clearCookie('google_access_token', cookieOptions);
  }

  private destroySession(req: Request): Promise<void> {
    return new Promise((resolve, reject) => {
      req.session.destroy((err) => {
        if (err) {
          this.logger.error('❌ Erro ao destruir sessão:', err);
          reject(err);
        } else {
          resolve();
        }
      });
    });
  }

  @Get('profile')
  @UseGuards(JwtGuard)
  getProfile(@Req() req: Request) {
    if (!req.user) {
      throw new UnauthorizedException('User not found in request');
    }

    const user = req.user as GoogleUser;
    this.logger.log(`👤 Acesso ao perfil: ${this.obfuscateEmail(user.email)}`);

    return {
      email: user.email,
      name: user.name,
      picture: user.picture,
      locale: user.locale,
      verified: user.verified,
    };
  }

  @Post('refresh')
  async refresh(
    @Body('refreshToken') refreshToken: string,
    @Res() res: Response,
  ) {
    const { accessToken, refreshToken: newRefreshToken } =
      await this.authService.refreshTokens(refreshToken);

    res.cookie('accessToken', accessToken, { httpOnly: true });
    res.cookie('refreshToken', newRefreshToken, { httpOnly: true });

    return res.json({ success: true });
  }
}
