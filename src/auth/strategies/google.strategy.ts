// src/auth/strategies/google.strategy.ts

// Importa o decorador `Injectable` do pacote @nestjs/common, que permite que a classe seja injetada como um provedor.
import { Injectable, Logger } from '@nestjs/common';

// Importa a classe `PassportStrategy` do pacote @nestjs/passport, que é usada para criar estratégias de autenticação.
import { PassportStrategy } from '@nestjs/passport';

// Importa a estratégia `Strategy` e o tipo `VerifyCallback` do pacote passport-google-oauth20.
// `Strategy` é a implementação da estratégia de autenticação OAuth2 do Google.
// `VerifyCallback` é uma função de callback que recebe os dados do usuário após a autenticação.
import { Strategy, VerifyCallback } from 'passport-google-oauth20';

// Define a classe `GoogleStrategy` como uma estratégia de autenticação usando o Passport.
// O decorador `@Injectable` permite que esta classe seja injetada em outros componentes do NestJS.
@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  // Logger personalizado para o GoogleStrategy, com um toque divertido!
  private readonly logger = new Logger(GoogleStrategy.name);

  constructor() {
    // Chama o construtor da classe pai (`PassportStrategy`) para configurar a estratégia do Google.
    super({
      clientID: process.env.GOOGLE_CLIENT_ID, // ID do cliente Google (obtido do ambiente).
      clientSecret: process.env.GOOGLE_CLIENT_SECRET, // Segredo do cliente Google (obtido do ambiente).
      callbackURL: process.env.GOOGLE_CALLBACK_URL, // URL de callback após a autenticação no Google.
      scope: ['email', 'profile'], // Escopos solicitados ao Google (email e perfil do usuário).
    });

    // Log divertido: confirma que a estratégia Google foi configurada com sucesso.
    this.logger.log('🚀 Estratégia Google configurada com sucesso!');
  }

  /**
   * Método `validate` chamado após a autenticação bem-sucedida no Google.
   * Este método recebe os dados do usuário e os processa antes de retorná-los ao controlador.
   *
   * @param accessToken - O token de acesso gerado pelo Google.
   * @param refreshToken - O token de atualização (não utilizado neste exemplo).
   * @param profile - O perfil do usuário retornado pelo Google.
   * @param done - A função de callback que deve ser chamada com os dados do usuário ou um erro.
   * @returns Retorna os dados do usuário autenticado.
   */
  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: VerifyCallback,
  ): Promise<any> {
    // Log intuitivo: inicia o processo de validação do usuário.
    this.logger.log('🔍 Validando usuário autenticado via Google...');

    // Extrai informações relevantes do perfil do usuário.
    const { name, emails, photos } = profile;

    // Cria um objeto de usuário com os dados necessários.
    const user = {
      email: emails[0].value, // E-mail do usuário.
      name: name.givenName, // Nome do usuário.
      picture: photos[0].value, // URL da foto do usuário.
      accessToken, // Token de acesso gerado pelo Google.
    };

    // Log divertido: exibe os dados do usuário extraídos.
    this.logger.log(`👤 Usuário autenticado: ${user.name} (${user.email})`);
    this.logger.log(`📸 Foto do usuário: ${user.picture}`);

    // Chama a função de callback `done` para retornar os dados do usuário ao controlador.
    done(null, user);

    // Log intuitivo: confirma que a validação foi concluída com sucesso.
    this.logger.log('✅ Validação do usuário concluída com sucesso!');
  }
}

/**Sugestões de Melhorias (Comentadas no Código):
Validação de Dados do Perfil:

Adicione uma verificação para garantir que os campos emails, name e photos estão presentes no perfil.

typescript
Copy
if (!emails || !name || !photos) {
  this.logger.error('❌ Dados do perfil do Google incompletos.');
  done(new Error('Dados do perfil incompletos'), null);
  return;
}
Suporte a Refresh Token:

Se necessário, você pode armazenar o refreshToken para renovar o accessToken quando ele expirar.

typescript
Copy
const user = {
  email: emails[0].value,
  name: name.givenName,
  picture: photos[0].value,
  accessToken,
  refreshToken, // Adiciona o refreshToken ao objeto do usuário.
};
Logs Estruturados:

Use logs estruturados (em formato JSON) para facilitar a análise em ferramentas de monitoramento.

typescript
Copy
this.logger.log({
  message: 'Usuário autenticado via Google',
  user: {
    email: user.email,
    name: user.name,
    picture: user.picture,
  },
});
Tratamento de Erros:

Adicione um bloco try-catch para capturar e tratar possíveis erros durante a validação.

typescript
Copy
try {
  // Processo de validação...
} catch (error) {
  this.logger.error(`💥 Erro durante a validação do usuário: ${error.message}`);
  done(error, null);
}
Configuração Dinâmica:

Permita que os escopos (scope) sejam configurados dinamicamente via variáveis de ambiente.

typescript
Copy
scope: process.env.GOOGLE_SCOPES?.split(',') || ['email', 'profile'],
Testes Automatizados:

Escreva testes unitários e de integração para garantir que a estratégia funcione corretamente em diferentes cenários.

Documentação:

Adicione uma documentação clara usando JSDoc para explicar o propósito da estratégia e como ela deve ser usada. */
