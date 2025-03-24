// src/auth/strategies/jwt.strategy.ts
import { Injectable, Logger } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';

interface JwtPayload {
  sub: string;
  email: string;
  name?: string;
  picture?: string;
  // Adicione outros campos do payload conforme necessário
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  private readonly logger = new Logger(JwtStrategy.name);

  constructor(configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        ExtractJwt.fromAuthHeaderAsBearerToken(),
        ExtractJwt.fromUrlQueryParameter('token'),
        (req) => req?.cookies?.jwt, // Para tokens em cookies
      ]),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_SECRET'),
      audience: configService.get<string>('JWT_AUDIENCE'),
      issuer: configService.get<string>('JWT_ISSUER'),
    });

    this.logger.log('🔐 Estratégia JWT configurada com sucesso!');
  }

  async validate(payload: JwtPayload) {
    // Validação básica do payload
    if (!payload.sub || !payload.email) {
      this.logger.error('❌ Payload JWT inválido: faltam campos obrigatórios');
      throw new Error('Payload JWT inválido');
    }

    this.logger.debug(
      `📄 Payload JWT decodificado: ${JSON.stringify(payload)}`,
    );
    this.logger.log(
      `👤 Usuário autenticado: ${payload.email.replace(/(?<=.).(?=.*@)/g, '*')}`,
    );

    return {
      userId: payload.sub,
      email: payload.email,
      name: payload.name,
      picture: payload.picture,
      // Adicione apenas os campos necessários para a aplicação
    };
  }
}

/**Sugestões de Melhorias (Comentadas no Código):
Validação de Payload:

Adicione uma verificação para garantir que o payload contém os campos necessários.

typescript
Copy
if (!payload.sub || !payload.email) {
  this.logger.error('❌ Payload do token JWT incompleto ou inválido.');
  throw new Error('Payload do token inválido');
}
Tipagem do Payload:

Crie uma interface ou tipo para o payload do token JWT, evitando o uso de any.

typescript
Copy
interface JwtPayload {
  sub: string; // ID do usuário.
  email: string; // E-mail do usuário.
}

async validate(payload: JwtPayload) {
  // ...
}
Logs Estruturados:

Use logs estruturados (em formato JSON) para facilitar a análise em ferramentas de monitoramento.

typescript
Copy
this.logger.log({
  message: 'Payload do token JWT',
  payload: {
    userId: payload.sub,
    email: payload.email,
  },
});
Tratamento de Erros:

Adicione um bloco try-catch para capturar e tratar possíveis erros durante a validação.

typescript
Copy
try {
  // Processo de validação...
} catch (error) {
  this.logger.error(`💥 Erro durante a validação do token JWT: ${error.message}`);
  throw error;
}
Configuração Dinâmica:

Permita que a chave secreta (secretOrKey) e outras opções sejam configuradas dinamicamente via variáveis de ambiente.

typescript
Copy
super({
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  ignoreExpiration: configService.get<boolean>('JWT_IGNORE_EXPIRATION', false),
  secretOrKey: configService.get<string>('JWT_SECRET'),
});
Testes Automatizados:

Escreva testes unitários e de integração para garantir que a estratégia funcione corretamente em diferentes cenários.

Documentação:

Adicione uma documentação clara usando JSDoc para explicar o propósito da estratégia e como ela deve ser usada.

 */
