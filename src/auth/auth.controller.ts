// src/auth/auth.controller.ts
import { Controller, Get, Req, UseGuards, Res } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { JwtGuard } from './guards/jwt.guard';
import { AuthService } from './auth.service';
import { Logger } from '@nestjs/common';

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(private readonly authService: AuthService) {}

  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth() {
    // Este método não precisa de implementação, pois o AuthGuard('google') redireciona automaticamente
    // o usuário para a página de login do Google.
  }

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleAuthRedirect(@Req() req, @Res() res) {
    const user = req.user;
    const token = this.authService.generateToken(user); // Gera o token JWT.

    // Log para mostrar o token gerado.
    this.logger.log(`Token JWT gerado: ${token}`);

    // Define o token como um cookie seguro.
    res.cookie('jwt', token, {
      httpOnly: true, // O cookie não pode ser acessado via JavaScript.
      secure: process.env.NODE_ENV === 'production', // Usa HTTPS em produção.
      sameSite: 'strict', // Protege contra ataques CSRF.
      maxAge: 3600000, // Tempo de expiração do cookie (1 hora).
      path: '/', // Define o caminho do cookie como "/".
    });

    // Log para confirmar que o cookie foi definido.
    this.logger.log('Cookie "jwt" definido com sucesso.');

    // Redireciona para a página de perfil.
    res.redirect(`/auth/profile?token=${token}`);
  }

  @Get('profile')
  @UseGuards(JwtGuard)
  getProfile(@Req() req) {
    // Log para mostrar os dados do usuário autenticado.
    this.logger.log(
      `Dados do usuário autenticado: ${JSON.stringify(req.user)}`,
    );

    return req.user; // Retorna os dados do usuário autenticado.
  }
}
