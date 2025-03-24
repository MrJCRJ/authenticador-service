// src/auth/auth.controller.ts
import { Controller, Get, Req, UseGuards, Res, Post } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { JwtGuard } from './guards/jwt.guard';
import { AuthService } from './auth.service';
import { Logger } from '@nestjs/common';
import { Response, Request } from 'express';
import axios, { AxiosError } from 'axios';
import * as jwt from 'jsonwebtoken';
import { ConfigService } from '@nestjs/config';
import { CookieOptions } from 'express';

interface GoogleAuthRequest extends Request {
  query: {
    state?: string;
    code?: string;
    error?: string;
    redirect?: string;
    message?: string; // Adicione esta linha
  };
}

interface GoogleUser {
  accessToken: string;
  refreshToken?: string;
  email: string;
  name: string;
  picture?: string;
  id?: string; // Adicione um ID se necessário
  locale?: string; // Idioma preferido
  verified?: boolean; // Se o email é verificado
}

declare module 'express-session' {
  interface SessionData {
    frontendOrigin?: string;
    user?: GoogleUser;
  }
}

@Controller('auth')
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
        this.configService.get('NODE_ENV') === 'production'
          ? 'none'
          : ('lax' as const),
      maxAge: 3600000,
      path: '/',
      domain: this.configService.get('COOKIE_DOMAIN') || undefined,
    };
  }

  private isValidUrl(url: string): boolean {
    try {
      new URL(url);
      return url.startsWith('http://') || url.startsWith('https://');
    } catch {
      return false;
    }
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
      default: 'Erro desconhecido durante a autenticação',
    };

    return messages[code] || messages.default;
  }

  @Get('google/init')
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
      this.configService.get('GOOGLE_CLIENT_ID')!,
    );
    authUrl.searchParams.append(
      'redirect_uri',
      this.configService.get('GOOGLE_CALLBACK_URL')!,
    );
    authUrl.searchParams.append('response_type', 'code');
    authUrl.searchParams.append('scope', 'email profile');
    authUrl.searchParams.append('state', state);
    authUrl.searchParams.append('access_type', 'offline');
    authUrl.searchParams.append('prompt', 'consent');

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
      if (!user?.accessToken) {
        throw new Error('Falha na autenticação do usuário');
      }

      const jwtToken = this.authService.generateToken(user);

      // Envie os dados para o frontend via query params ou cookies
      const redirectUrl = new URL(frontendOrigin);
      redirectUrl.searchParams.append('token', jwtToken);
      redirectUrl.searchParams.append(
        'user',
        JSON.stringify({
          email: user.email,
          name: user.name,
          picture: user.picture,
          // Não envie tokens sensíveis aqui
        }),
      );

      return res.redirect(redirectUrl.toString());
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : 'Erro desconhecido';
      this.logger.error(`❌ Erro no callback: ${errorMessage}`);
      return res.redirect('/auth/error?message=auth_failed');
    }
  }

  @Post('logout')
  async logout(@Req() req: Request, @Res() res: Response) {
    this.logger.log('🔑 Iniciando logout...');

    let googleAccessToken: string | undefined;
    if (req.cookies.google_access_token) {
      googleAccessToken = req.cookies.google_access_token;
    } else if (req.cookies.jwt) {
      try {
        const decoded = jwt.verify(
          req.cookies.jwt,
          this.configService.get('JWT_SECRET'),
        ) as { accessToken?: string };
        googleAccessToken = decoded.accessToken;
      } catch (error) {
        this.logger.warn('⚠️ Não foi possível recuperar o token do JWT');
      }
    }

    if (googleAccessToken) {
      try {
        await axios.post('https://oauth2.googleapis.com/revoke', null, {
          params: { token: googleAccessToken },
        });
        this.logger.log('🔑 Token do Google revogado com sucesso!');
      } catch (error) {
        const errorMessage =
          error instanceof Error ? error.message : 'Erro desconhecido';
        this.logger.error('❌ Erro ao revogar token:', errorMessage);
      }
    }

    const cookieOptions = this.getCookieOptions();
    res.clearCookie('jwt', cookieOptions);
    res.clearCookie('google_access_token', cookieOptions);

    req.session.destroy((err) => {
      if (err) {
        this.logger.error('❌ Erro ao destruir sessão:', err);
      }
    });

    this.logger.log('👋 Logout realizado com sucesso');
    return res.status(200).json({ success: true });
  }

  @Get('profile')
  @UseGuards(JwtGuard)
  getProfile(@Req() req: Request) {
    const user = req.user as GoogleUser;
    this.logger.log(`👤 Acesso ao perfil: ${user.email}`);

    return {
      email: user.email,
      name: user.name,
      picture: user.picture,
      locale: user.locale,
      verified: user.verified,
      // Exclua dados sensíveis como tokens
    };
  }
}

/** Sugestões de Melhoria (Comentadas no Código):
    Rota do perfil do usuário autenticado.
    Requer autenticação JWT válida
  

   Sugestão de melhoria: Adicionar endpoint de logout
   @Get('logout')
   logout(@Res() res) {
    res.clearCookie('jwt');
     this.logger.log('🚪 Usuário deslogado com sucesso');
     return res.redirect('/');
   
     Sugestões de Melhoria (Para Implementar):
Validação de Dados do Usuário

typescript
Copy
// Antes de gerar o token:
// if (!this.authService.isValidUser(user)) {
//   this.logger.warn(`Tentativa de login com usuário inválido: ${user.email}`);
//   throw new UnauthorizedException('Usuário não autorizado');
// }
Monitoramento de Atividade

typescript
Copy
// Após o login bem-sucedido:
// this.authService.trackLoginActivity(user.id, req.ip);
Tokens de Atualização

typescript
Copy
// Gerar refresh token junto com o access token:
// const { accessToken, refreshToken } = this.authService.generateTokens(user);
// res.cookie('refreshToken', refreshToken, { ... });
Proteção Contra Flood

typescript
Copy
// Adicionar decorador de rate limiting:
// @Throttle({ default: { limit: 5, ttl: 30000 } })
Tratamento de Erros Global

typescript
Copy
// Adicionar filtro de exceções personalizado:
// @UseFilters(new AuthExceptionFilter())


Exemplo de Saída de Logs:
Copy
🔑 Iniciando autenticação via Google...
🔄 Processando callback do Google...
🎫 Token JWT gerado: eyJhbGciOiJIUzI1NiIs... (truncado por segurança)
🍪 Cookie JWT definido com sucesso!
👤 Acesso ao perfil: j****@gmail.com

  */
