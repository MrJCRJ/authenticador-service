// src/auth/guards/jwt.guard.ts
import { Injectable, ExecutionContext, Logger } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtGuard extends AuthGuard('jwt') {
  private readonly logger = new Logger(JwtGuard.name);

  canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();

    // Log para mostrar todos os cookies recebidos.
    this.logger.log(`Cookies recebidos: ${JSON.stringify(request.cookies)}`);

    const tokenFromUrl = request.query.token; // Extrai o token da URL.
    const tokenFromCookie = request.cookies?.jwt;

    const token = tokenFromUrl || tokenFromCookie;

    // Log para verificar se o cookie está presente.
    this.logger.log(`Cookie 'jwt' encontrado: ${!!token}`);

    if (token) {
      // Log para mostrar o token extraído.
      this.logger.log(`Token JWT extraído do cookie: ${token}`);

      // Define o token no cabeçalho Authorization.
      request.headers['authorization'] = `Bearer ${token}`;

      // Log para confirmar que o token foi definido no cabeçalho.
      this.logger.log(
        `Token JWT definido no cabeçalho Authorization: Bearer ${token}`,
      );
    } else {
      this.logger.warn('Nenhum token JWT encontrado no cookie.');
    }

    return super.canActivate(context);
  }
}
