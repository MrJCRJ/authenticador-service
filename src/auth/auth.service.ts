// src/auth/auth.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as Joi from 'joi';

interface GoogleUser {
  id?: string;
  sub?: string;
  email: string;
  name: string;
  picture?: string;
  locale?: string;
  verified?: boolean;
  accessToken: string;
  refreshToken?: string;
}

interface JwtPayload {
  sub: string;
  email: string;
  name?: string;
  picture?: string;
  locale?: string;
  verified?: boolean;
  iat?: number;
  exp?: number;
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly payloadSchema = Joi.object({
    sub: Joi.string().required(),
    email: Joi.string().email().required(),
    name: Joi.string().optional(),
    picture: Joi.string().uri().optional(),
    locale: Joi.string().optional(),
    verified: Joi.boolean().optional(),
    iat: Joi.number().optional(),
    exp: Joi.number().optional(),
  });

  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  /**
   * Gera um token JWT seguro com informações do usuário
   */
  generateToken(user: GoogleUser): string {
    const payload: JwtPayload = {
      sub: user.id || user.sub || user.email,
      email: user.email,
      name: user.name,
      picture: user.picture,
      locale: user.locale,
      verified: user.verified,
    };

    this.validatePayload(payload);

    this.logger.log(
      `🔐 Gerando token para: ${user.email.replace(/(?<=.).(?=.*@)/g, '*')}`,
    );
    this.logger.debug(
      `Token payload: ${JSON.stringify({ ...payload, sub: '***' })}`,
    );

    return this.jwtService.sign(payload, {
      expiresIn: this.configService.get('JWT_EXPIRES_IN', '1h'),
      secret: this.configService.get('JWT_SECRET'),
      issuer: this.configService.get('JWT_ISSUER'),
      audience: this.configService.get('JWT_AUDIENCE'),
    });
  }

  /**
   * Validação completa do token JWT
   */
  async validateToken(token: string): Promise<GoogleUser> {
    try {
      const payload = this.jwtService.verify<JwtPayload>(token, {
        secret: this.configService.get('JWT_SECRET'),
        issuer: this.configService.get('JWT_ISSUER'),
        audience: this.configService.get('JWT_AUDIENCE'),
      });

      this.validatePayload(payload);

      return {
        id: payload.sub,
        email: payload.email,
        name: payload.name,
        picture: payload.picture,
        locale: payload.locale,
        verified: payload.verified,
        accessToken: '', // Preenchido posteriormente
      };
    } catch (error) {
      this.logger.error(
        `❌ Falha na validação: ${error instanceof Error ? error.message : 'Erro desconhecido'}`,
      );
      throw new Error('Token inválido ou expirado');
    }
  }

  /**
   * Valida a estrutura do payload JWT
   */
  private validatePayload(payload: JwtPayload): void {
    const { error } = this.payloadSchema.validate(payload);
    if (error) {
      this.logger.error(`❌ Payload JWT inválido: ${error.message}`);
      throw new Error('Payload JWT inválido');
    }
  }

  /**
   * Decodificação segura para logs
   */
  decodeToken(token: string): JwtPayload | null {
    try {
      const payload = this.jwtService.decode(token) as JwtPayload;
      return payload
        ? { ...payload, email: payload.email?.replace(/(?<=.).(?=.*@)/g, '*') }
        : null;
    } catch (error) {
      this.logger.error(
        `❌ Falha ao decodificar token: ${error instanceof Error ? error.message : 'Erro desconhecido'}`,
      );
      return null;
    }
  }
}

/**Sugestões de Melhoria (Para Implementar):
Tipagem do Payload:

Crie uma interface para o payload do token JWT, evitando o uso de any.

typescript
Copy
interface JwtPayload {
  email: string;
  sub: string; // ID ou nome do usuário.
}

generateToken(user: { email: string; name: string }): string {
  const payload: JwtPayload = { email: user.email, sub: user.name };
  return this.jwtService.sign(payload);
}
Suporte a Refresh Tokens:

Adicione métodos para gerar e validar refresh tokens.

typescript
Copy
generateRefreshToken(user: any): string {
  const payload = { email: user.email, sub: user.name, type: 'refresh' };
  return this.jwtService.sign(payload, { expiresIn: '7d' });
}

validateRefreshToken(token: string): any {
  try {
    return this.jwtService.verify(token);
  } catch (error) {
    return null;
  }
}
Auditoria de Tokens:

Registre a geração e validação de tokens em um sistema de auditoria.

typescript
Copy
generateToken(user: any): string {
  const payload = { email: user.email, sub: user.name };
  const token = this.jwtService.sign(payload);

  // Log de auditoria.
  this.logger.log(`📝 Auditoria: Token gerado para ${user.email}`);
  return token;
}
Configuração Dinâmica:

Use o ConfigService para carregar opções de expiração e chaves secretas dinamicamente.

typescript
Copy
constructor(
  private readonly jwtService: JwtService,
  private readonly configService: ConfigService,
) {}

generateToken(user: any): string {
  const payload = { email: user.email, sub: user.name };
  return this.jwtService.sign(payload, {
    expiresIn: this.configService.get<string>('JWT_EXPIRES_IN', '1h'),
  });
}
Testes Automatizados:

Adicione testes unitários para garantir que os métodos funcionem corretamente.

typescript
Copy
describe('AuthService', () => {
  let authService: AuthService;
  let jwtService: JwtService;

  beforeEach(() => {
    jwtService = new JwtService({ secret: 'test-secret' });
    authService = new AuthService(jwtService);
  });

  it('deve gerar um token JWT válido', () => {
    const token = authService.generateToken({ email: 'test@test.com', name: 'Test' });
    expect(token).toBeDefined();
  });
});
Segurança:

Adicione validações adicionais para garantir que o payload do token contenha os campos necessários.

typescript
Copy
validateToken(token: string): any {
  try {
    const payload = this.jwtService.verify(token);
    if (!payload.email || !payload.sub) {
      throw new Error('Payload do token inválido');
    }
    return payload;
  } catch (error) {
    return null;
  }
}
Exemplo de Saída de Logs:
Copy
🔐 Gerando token JWT para o usuário: joao@gmail.com
🎫 Token JWT gerado: eyJhbGciOiJIUzI1Ni... (truncado por segurança)
🔍 Validando token JWT: eyJhbGciOiJIUzI1Ni...
✅ Token JWT válido para o usuário: joao@gmail.com
 */
