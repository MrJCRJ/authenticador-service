import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Controller('auth')
export class AuthController {
  // Rota para iniciar o login com Google
  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth() {
    // Esse método apenas redireciona para o Google
  }

  // Callback do Google após login
  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  googleAuthRedirect(@Req() req) {
    return req.user; // Retorna os dados do usuário autenticado
  }
}
