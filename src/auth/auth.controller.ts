// src/auth/auth.controller.ts
import { Controller, Get, Req, UseGuards, Res } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { JwtGuard } from './guards/jwt.guard';
import { AuthService } from './auth.service';
import { Logger } from '@nestjs/common';

@Controller('auth')
export class AuthController {
  // Logger personalizado com emojis para logs divertidos e intuitivos 🎉
  private readonly logger = new Logger(AuthController.name);

  constructor(private readonly authService: AuthService) {}

  /**
   * Rota de autenticação via Google.
   * Redireciona o usuário para a página de login do Google automaticamente.
   */
  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth() {
    // Log divertido: início do processo de autenticação
    this.logger.log('🔑 Iniciando autenticação via Google...');
    // Não é necessária implementação - o AuthGuard cuida do redirecionamento!
  }

  /**
   * Callback da autenticação Google.
   * Gera um token JWT, define um cookie seguro e redireciona para o perfil.
   */
  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleAuthRedirect(@Req() req, @Res() res) {
    // Log intuitivo: processo de callback iniciado
    this.logger.log('🔄 Processando callback do Google...');

    // Sugestão de melhoria: Validar se o usuário existe antes de gerar o token
    if (!req.user) {
      this.logger.error('❌ Nenhum usuário retornado pelo Google');
      return res.redirect('/auth/error');
    }

    const user = req.user;
    // Gera o token JWT com dados do usuário
    const token = this.authService.generateToken(user);

    // Log divertido: token gerado (⚠️ cuidado com logs sensíveis em produção!)
    this.logger.log(
      `🎫 Token JWT gerado: ${token.slice(0, 15)}... (truncado por segurança)`,
    );

    // Configurações seguras para o cookie
    const cookieOptions = {
      httpOnly: true, // Blinda contra ataques XSS
      secure: process.env.NODE_ENV === 'production', // HTTPS apenas em produção
      sameSite: 'strict' as const, // Proteção contra CSRF
      maxAge: 3600000, // 1 hora de validade
      path: '/', // Disponível em todas as rotas
    };

    // Define o cookie JWT na resposta
    res.cookie('jwt', token, cookieOptions);
    this.logger.log('🍪 Cookie JWT definido com sucesso!');

    // Sugestão de melhoria: Evitar token na URL por segurança
    // Redireciona para o perfil usando apenas o cookie
    res.redirect('/auth/profile');
  }
}
/** Sugestões de Melhoria (Comentadas no Código):
    Rota do perfil do usuário autenticado.
    Requer autenticação JWT válida.

  @Get('profile')
  @UseGuards(JwtGuard))
  getProfile(@Req() req) {
     Log intuitivo com dados mascarados por segurança
    this.logger.log(`👤 Acesso ao perfil: ${req.user.email.replace(/(?<=.).(?=.*@)/g, '*')}`);
    this.logger.debug(`📊 Dados completos do usuário: ${JSON.stringify(req.user)}`);

    return req.user;
  

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
