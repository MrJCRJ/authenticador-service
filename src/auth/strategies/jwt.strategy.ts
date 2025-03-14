// src/auth/strategies/jwt.strategy.ts

// Importa o decorador `Injectable` e a classe `Logger` do pacote @nestjs/common.
// `Injectable` permite que a classe seja injetada como um provedor.
// `Logger` é usado para registrar mensagens de log.
import { Injectable, Logger } from '@nestjs/common';

// Importa a classe `PassportStrategy` do pacote @nestjs/passport, que é usada para criar estratégias de autenticação.
import { PassportStrategy } from '@nestjs/passport';

// Importa as funções `ExtractJwt` e `Strategy` do pacote passport-jwt.
// `ExtractJwt` fornece métodos para extrair o token JWT de diferentes fontes (cabeçalho, corpo, etc.).
// `Strategy` é a implementação da estratégia de autenticação JWT.
import { ExtractJwt, Strategy } from 'passport-jwt';

// Importa o `ConfigService` do pacote @nestjs/config, que permite acessar variáveis de ambiente.
import { ConfigService } from '@nestjs/config';

// Define a classe `JwtStrategy` como uma estratégia de autenticação usando o Passport.
// O decorador `@Injectable` permite que esta classe seja injetada em outros componentes do NestJS.
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  // Logger personalizado para o JwtStrategy, com um toque divertido!
  private readonly logger = new Logger(JwtStrategy.name);

  constructor(private readonly configService: ConfigService) {
    // Chama o construtor da classe pai (`PassportStrategy`) para configurar a estratégia JWT.
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(), // Extrai o token do cabeçalho Authorization.
      ignoreExpiration: false, // Não ignora tokens expirados.
      secretOrKey: configService.get<string>('JWT_SECRET'), // Chave secreta para validar o token.
    });

    // Log divertido: confirma que a estratégia JWT foi configurada com sucesso.
    this.logger.log('🔐 Estratégia JWT configurada com sucesso!');
  }

  /**
   * Método `validate` chamado após a validação bem-sucedida do token JWT.
   * Este método recebe o payload do token e o processa antes de retorná-lo ao controlador.
   *
   * @param payload - O payload do token JWT (contém informações como ID do usuário, e-mail, etc.).
   * @returns Retorna um objeto com os dados do usuário extraídos do payload.
   */
  async validate(payload: any) {
    // Log intuitivo: exibe o payload do token JWT.
    this.logger.log(`📄 Payload do token JWT: ${JSON.stringify(payload)}`);

    // Log divertido: exibe informações do usuário extraídas do payload.
    this.logger.log(
      `👤 Usuário autenticado: ID ${payload.sub}, E-mail ${payload.email}`,
    );

    // Retorna o payload do token (geralmente contém informações do usuário).
    return { userId: payload.sub, email: payload.email };
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
