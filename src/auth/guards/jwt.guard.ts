// src/auth/guards/jwt.guard.ts
import {
  Injectable,
  ExecutionContext,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import * as jwt from 'jsonwebtoken';

interface JwtPayloadWithExp extends jwt.JwtPayload {
  exp: number;
}

@Injectable()
export class JwtGuard extends AuthGuard('jwt') {
  private readonly logger = new Logger(JwtGuard.name);
  private readonly tokenCache = new Map<string, boolean>();
  private readonly cookieKey = process.env.JWT_COOKIE_KEY || 'jwt';
  private readonly customHeader =
    process.env.JWT_CUSTOM_HEADER || 'x-custom-token';

  canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();

    try {
      const token = this.extractTokenFromRequest(request);
      this.logStructuredTokenInfo(token, request);

      if (!token) {
        this.logger.warn(
          '⚠️ Nenhum token JWT encontrado nas fontes disponíveis.',
        );
        throw new UnauthorizedException('Token de autenticação não fornecido.');
      }

      this.validateTokenBasic(token);
      this.validateTokenFormat(token);

      if (this.tokenCache.has(token)) {
        this.logger.debug('♻️ Token encontrado no cache - autenticação rápida');
        return true;
      }

      request.headers['authorization'] = `Bearer ${token}`;
      this.logger.log(
        `🔑 Token JWT definido no header: Bearer ${token.substring(0, 15)}...`,
      );

      const result = super.canActivate(context);

      if (result) {
        this.tokenCache.set(token, true);
      }

      return result;
    } catch (error) {
      this.logger.error(`💥 Erro durante a autenticação: ${error}`);
      throw new UnauthorizedException(error || 'Falha na autenticação');
    }
  }

  private extractTokenFromRequest(request: any): string | undefined {
    return (
      request.query?.token ||
      request.cookies?.[this.cookieKey] ||
      request.body?.token ||
      request.headers[this.customHeader] ||
      request.headers?.authorization?.split(' ')[1]
    );
  }

  private validateTokenBasic(token: string): void {
    if (typeof token !== 'string' || token.trim() === '') {
      this.logger.error('❌ Token inválido: deve ser uma string não vazia.');
      throw new UnauthorizedException('Token JWT inválido.');
    }
  }

  private validateTokenFormat(token: string): void {
    const parts = token.split('.');
    if (parts.length !== 3) {
      this.logger.error(
        '❌ Formato do token JWT inválido (deveria ser header.payload.signature).',
      );
      throw new UnauthorizedException('Formato do token inválido.');
    }

    try {
      const decoded = jwt.decode(token);

      if (!decoded) {
        throw new UnauthorizedException('Token JWT não pôde ser decodificado.');
      }

      // Verificação segura da expiração
      if (typeof decoded === 'object' && 'exp' in decoded) {
        const payload = decoded as JwtPayloadWithExp;
        if (payload.exp && payload.exp < Date.now() / 1000) {
          this.logger.error('❌ Token JWT expirado.');
          throw new UnauthorizedException('Token expirado.');
        }
      }
    } catch (error) {
      this.logger.error(`❌ Falha na decodificação do token: ${error}`);
      throw new UnauthorizedException('Token JWT inválido.');
    }
  }

  private logStructuredTokenInfo(
    token: string | undefined,
    request: any,
  ): void {
    let source = 'não encontrado';
    if (token) {
      if (request.query?.token) source = 'URL';
      else if (request.cookies?.[this.cookieKey]) source = 'Cookie';
      else if (request.body?.token) source = 'Body';
      else if (request.headers[this.customHeader])
        source = `Header ${this.customHeader}`;
      else if (request.headers?.authorization) source = 'Header Authorization';
    }

    this.logger.debug({
      message: 'Informações do Token JWT',
      tokenPresent: !!token,
      tokenSource: source,
      tokenPrefix: token ? token.substring(0, 5) + '...' : null,
      timestamp: new Date().toISOString(),
    });
  }
}

/**Próximas Melhorias Possíveis:
Blacklist de Tokens - Para implementar logout

Rate Limiting - Prevenir abuso

Cache com TTL - Limpar tokens expirados do cache

Health Check - Verificar integridade do guard

Testes Automatizados - Unitários e de integração */
