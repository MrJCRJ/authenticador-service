// src/auth/strategies/jwt.strategy.ts
import { Injectable, Logger } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  private readonly logger = new Logger(Strategy.name);
  constructor(private readonly configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(), // Extrai o token do cabeçalho Authorization.
      ignoreExpiration: false, // Não ignora tokens expirados.
      secretOrKey: configService.get<string>('JWT_SECRET'), // Chave secreta para validar o token.
    });
  }

  async validate(payload: any) {
    // Log para mostrar o payload do token.
    this.logger.log(`Payload do token JWT: ${JSON.stringify(payload)}`);

    // Retorna o payload do token (geralmente contém informações do usuário).
    return { userId: payload.sub, email: payload.email };
  }
}
