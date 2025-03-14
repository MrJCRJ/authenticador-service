// src/auth/auth.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  // Logger personalizado para o AuthService, com emojis para logs divertidos e intuitivos 🎉
  private readonly logger = new Logger(AuthService.name);

  constructor(private readonly jwtService: JwtService) {}

  /**
   * Gera um token JWT com base nos dados do usuário.
   *
   * @param user - Objeto contendo informações do usuário (email e nome).
   * @returns Token JWT assinado.
   */
  generateToken(user: any): string {
    // Cria o payload do token com informações do usuário.
    const payload = { email: user.email, sub: user.name };

    // Log intuitivo: geração do token.
    this.logger.log(`🔐 Gerando token JWT para o usuário: ${user.email}`);

    // Gera e retorna o token JWT.
    const token = this.jwtService.sign(payload);

    // Log divertido: token gerado (⚠️ cuidado com logs sensíveis em produção!).
    this.logger.log(
      `🎫 Token JWT gerado: ${token.slice(0, 15)}... (truncado por segurança)`,
    );

    return token;
  }

  /**
   * Valida um token JWT.
   *
   * @param token - Token JWT a ser validado.
   * @returns Payload do token se válido, ou `null` se inválido ou expirado.
   */
  validateToken(token: string): any {
    // Log intuitivo: início da validação do token.
    this.logger.log(`🔍 Validando token JWT: ${token.slice(0, 15)}...`);

    try {
      // Verifica e decodifica o token.
      const payload = this.jwtService.verify(token);

      // Log divertido: token validado com sucesso.
      this.logger.log(`✅ Token JWT válido para o usuário: ${payload.email}`);

      return payload;
    } catch (error) {
      // Verifica se o erro é uma instância de Error antes de acessar a propriedade message.
      if (error instanceof Error) {
        // Log de erro: token inválido ou expirado.
        this.logger.error(`❌ Falha na validação do token: ${error.message}`);
      } else {
        // Log de erro genérico caso o erro não seja uma instância de Error.
        this.logger.error('❌ Falha na validação do token: Erro desconhecido');
      }

      return null; // Retorna null para tokens inválidos ou expirados.
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
