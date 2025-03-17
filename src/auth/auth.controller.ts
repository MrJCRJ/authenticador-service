// src/auth/auth.controller.ts
import { Controller, Get, Req, UseGuards, Res, Post } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { JwtGuard } from './guards/jwt.guard';
import { AuthService } from './auth.service';
import { Logger } from '@nestjs/common';
import { Response, Request } from 'express';
import axios, { AxiosError } from 'axios';

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(private readonly authService: AuthService) {}

  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth() {
    this.logger.log('🔑 Iniciando autenticação via Google...');
  }

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleAuthRedirect(@Req() req, @Res() res: Response) {
    this.logger.log('🔄 Processando callback do Google...');

    if (!req.user) {
      this.logger.error('❌ Nenhum usuário retornado pelo Google');
      return res.redirect('/auth/error');
    }

    const user = req.user;
    const googleAccessToken = req.user.accessToken; // Token de acesso do Google

    // Armazena o token de acesso do Google em um cookie seguro
    res.cookie('google_access_token', googleAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 3600000, // 1 hora de validade
      path: '/',
    });

    this.logger.log(
      '🍪 Cookie do token de acesso do Google definido com sucesso!',
    );

    // Gera o token JWT da aplicação
    const jwtToken = this.authService.generateToken(user);
    res.cookie('jwt', jwtToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 3600000, // 1 hora de validade
      path: '/',
    });

    this.logger.log('🍪 Cookie JWT definido com sucesso!');

    // Redireciona para o frontend
    res.redirect('http://localhost:5500');
  }

  @Post('logout')
  async logout(@Req() req: Request, @Res() res: Response) {
    const googleAccessToken = req.cookies.google_access_token; // Obtém o token de acesso do Google

    if (googleAccessToken) {
      try {
        // Revoga o token de acesso do Google
        await axios.post('https://oauth2.googleapis.com/revoke', null, {
          params: {
            token: googleAccessToken, // Token de acesso do Google
          },
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
    }

    // Remove os cookies
    res.clearCookie('jwt', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/',
    });

    res.clearCookie('google_access_token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/',
    });

    this.logger.log('👋 Usuário deslogado com sucesso!');

    // Retorna uma resposta de sucesso
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
