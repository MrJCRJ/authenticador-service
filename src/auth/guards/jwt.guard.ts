// src/auth/guards/jwt.guard.ts
import {
  Injectable,
  ExecutionContext,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import * as jwt from 'jsonwebtoken';
import { Request } from 'express';

interface JwtPayloadWithUser extends jwt.JwtPayload {
  email: string;
  name?: string;
  picture?: string;
}

@Injectable()
export class JwtGuard extends AuthGuard('jwt') {
  private readonly logger = new Logger(JwtGuard.name);
  private readonly tokenCache = new Map<
    string,
    { valid: boolean; user: any }
  >();

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();

    try {
      const token = this.extractToken(request);

      if (!token) {
        this.logger.warn('⚠️ Nenhum token JWT encontrado');
        throw new UnauthorizedException('Token não fornecido');
      }

      this.validateTokenStructure(token);

      // Verifica cache primeiro
      const cached = this.tokenCache.get(token);
      if (cached?.valid) {
        this.logger.debug('♻️ Usando token do cache');
        request.user = cached.user; // Garante que o user está anexado
        return true;
      }

      // Validação completa do token
      const payload = this.verifyToken(token);
      if (!payload.email) {
        throw new UnauthorizedException('Token não contém email');
      }

      // Chama a estratégia JWT padrão
      const parentResult = (await super.canActivate(context)) as boolean;
      if (!parentResult) {
        return false;
      }

      // Anexa user à requisição (garantia extra)
      if (!request.user) {
        request.user = {
          email: payload.email,
          name: payload.name,
          picture: payload.picture,
        };
      }

      // Atualiza cache
      this.tokenCache.set(token, {
        valid: true,
        user: request.user,
      });

      this.logger.log(`✅ Autenticação válida para: ${payload.email}`);
      return true;
    } catch (error) {
      this.logger.error(`❌ Falha na autenticação: ${error}`);
      throw new UnauthorizedException(error || 'Falha na autenticação');
    }
  }

  private extractToken(request: Request): string | null {
    return (
      request.cookies?.jwt ||
      request.headers.authorization?.split(' ')[1] ||
      (request.query?.token as string) ||
      null
    );
  }

  private validateTokenStructure(token: string): void {
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new UnauthorizedException('Formato de token inválido');
    }
  }

  private verifyToken(token: string): JwtPayloadWithUser {
    try {
      const payload = jwt.decode(token) as JwtPayloadWithUser;

      if (!payload) {
        throw new UnauthorizedException('Token inválido');
      }

      // Verifica expiração
      if (payload.exp && payload.exp < Date.now() / 1000) {
        throw new UnauthorizedException('Token expirado');
      }

      return payload;
    } catch (error) {
      throw new UnauthorizedException('Falha ao verificar token');
    }
  }
}
