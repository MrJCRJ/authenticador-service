// /src/auth/auth.controller.ts

// Importa os decoradores e funcionalidades necessárias do NestJS.
import { Controller, Get, Req, UseGuards } from '@nestjs/common';

// Importa o AuthGuard do pacote @nestjs/passport para proteger rotas com autenticação.
import { AuthGuard } from '@nestjs/passport';

// Define o controlador de autenticação com o prefixo de rota 'auth'.
// Todas as rotas definidas neste controlador serão prefixadas com '/auth'.
@Controller('auth')
export class AuthController {
  /**
   * Rota para iniciar o processo de autenticação com o Google.
   * Quando o usuário acessa esta rota, ele é redirecionado para a página de login do Google.
   * O guardião AuthGuard('google') gerencia o fluxo de autenticação OAuth2.
   */
  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth() {
    // Este método não precisa de implementação, pois o AuthGuard('google') redireciona automaticamente
    // o usuário para a página de login do Google.
  }

  /**
   * Rota de callback do Google após o login.
   * Após o usuário autenticar-se no Google, ele é redirecionado para esta rota.
   * O guardião AuthGuard('google') processa o código de autorização e obtém os dados do usuário.
   *
   * @param req - O objeto de requisição HTTP, que contém os dados do usuário autenticado.
   * @returns Os dados do usuário autenticado.
   */
  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  googleAuthRedirect(@Req() req) {
    // Retorna os dados do usuário autenticado, que são anexados ao objeto de requisição pelo Passport.js.
    return req.user;
  }
}
