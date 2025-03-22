// src/auth/auth.controller.ts
import { Controller, Get, Req, UseGuards, Res, Post } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { JwtGuard } from './guards/jwt.guard';
import { AuthService } from './auth.service';
import { Logger } from '@nestjs/common';
import { Response, Request } from 'express';
import axios, { AxiosError } from 'axios';
import 'express-session'; // Importa o módulo express-session para estender suas definições
import * as jwt from 'jsonwebtoken';

declare module 'express-session' {
  interface SessionData {
    frontendOrigin?: string; // Adiciona a propriedade frontendOrigin ao tipo SessionData
  }
}

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(private readonly authService: AuthService) {}

  @Get('google/init')
  async googleAuthInit(@Req() req: Request, @Res() res: Response) {
    this.logger.log('🔗 Iniciando autenticação com Google...');
    this.logger.log(`🔗 Query parameters: ${JSON.stringify(req.query)}`);

    const redirectUrl = req.query.redirect as string;

    if (redirectUrl) {
      req.session.frontendOrigin = redirectUrl;
      this.logger.log(
        `🔗 Frontend de origem armazenado na sessão: ${redirectUrl}`,
      );
    } else {
      this.logger.warn('⚠️ Nenhuma URL de frontend fornecida.');
    }

    const state = encodeURIComponent(redirectUrl);
    res.redirect(`/auth/google?state=${state}`);
  }

  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth() {
    this.logger.log('🔄 Redirecionando para o Google...');
  }

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleAuthRedirect(@Req() req, @Res() res: Response) {
    this.logger.log('🔄 Processando callback do Google...');
    this.logger.log(`🔗 Sessão atual: ${JSON.stringify(req.session)}`);
    this.logger.log(`🔗 Usuário autenticado: ${JSON.stringify(req.user)}`);

    if (!req.user) {
      this.logger.error('❌ Nenhum usuário retornado pelo Google');
      return res.redirect('/auth/error');
    }

    const user = req.user;
    const googleAccessToken = req.user.accessToken;

    const frontendOrigin = decodeURIComponent(req.query.state);

    if (!frontendOrigin) {
      this.logger.error('❌ Nenhuma URL de frontend encontrada na sessão.');
      return res.redirect('/auth/error');
    }

    res.cookie('google_access_token', googleAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
      maxAge: 3600000,
      path: '/',
    });

    this.logger.log(
      '🍪 Cookie do token de acesso do Google definido com sucesso!',
    );

    const jwtToken = this.authService.generateToken({
      ...user,
      googleAccessToken,
    });
    res.cookie('jwt', jwtToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
      maxAge: 3600000,
      path: '/',
    });

    this.logger.log('🍪 Cookie JWT definido com sucesso!');

    res.redirect(frontendOrigin);
  }

  @Post('logout')
  async logout(@Req() req: Request, @Res() res: Response) {
    this.logger.log('🔑 Iniciando logout...');
    let googleAccessToken = req.cookies.google_access_token;

    // Se não encontrou no cookie, tenta pegar do JWT
    if (!googleAccessToken && req.cookies.jwt) {
      try {
        const decoded = jwt.verify(
          req.cookies.jwt,
          process.env.JWT_SECRET,
        ) as any;
        googleAccessToken = decoded.googleAccessToken;
      } catch (error) {
        this.logger.warn('⚠️ Não foi possível recuperar o token do JWT');
      }
    }

    if (googleAccessToken) {
      this.logger.log('🔑 Revogando token do Google...');
      try {
        await axios.post('https://oauth2.googleapis.com/revoke', null, {
          params: { token: googleAccessToken },
        });
        this.logger.log('🔑 Token do Google revogado com sucesso!');
      } catch (error) {
        if (error instanceof AxiosError) {
          this.logger.error(
            '❌ Erro ao revogar o token do Google:',
            error.message,
          );
        } else {
          this.logger.error(
            '❌ Erro desconhecido ao revogar o token do Google:',
            error,
          );
        }
      }
    } else {
      this.logger.warn('⚠️ Nenhum token do Google encontrado para revogação.');
    }

    // Remove os cookies
    res.clearCookie('jwt', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
      path: '/',
    });

    res.clearCookie('google_access_token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
      path: '/',
    });

    res.clearCookie('frontend_origin', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
      path: '/',
    });

    this.logger.log('👋 Usuário deslogado com sucesso!');

    res
      .status(200)
      .json({ success: true, message: 'Logout realizado com sucesso' });
  }

  @Get('profile')
  @UseGuards(JwtGuard)
  getProfile(@Req() req) {
    this.logger.log(
      `👤 Acesso ao perfil: ${req.user.email.replace(/(?<=.).(?=.*@)/g, '*')}`,
    );
    this.logger.debug(
      `📊 Dados completos do usuário: ${JSON.stringify(req.user)}`,
    );

    return req.user;
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
