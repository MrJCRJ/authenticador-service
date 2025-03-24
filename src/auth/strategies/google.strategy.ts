// src/auth/strategies/google.strategy.ts
import { Injectable, Logger } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  private readonly logger = new Logger(GoogleStrategy.name);

  constructor() {
    super({
      clientID: process.env.GOOGLE_CLIENT_ID, // ID do cliente Google.
      clientSecret: process.env.GOOGLE_CLIENT_SECRET, // Segredo do cliente Google.
      callbackURL: process.env.GOOGLE_CALLBACK_URL, // URL de callback após a autenticação.
      scope: ['email', 'profile'], // Escopos solicitados ao Google.
      passReqToCallback: true, // Passa a requisição para o método `validate`.
      state: true, // Habilita o uso de parâmetros personalizados.
      proxy: true, // Habilita o suporte a proxies reversos.
    });

    this.logger.log('🚀 Estratégia Google configurada com sucesso!');
  }

  async validate(
    req: any, // A requisição é passada graças ao `passReqToCallback`.
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: VerifyCallback,
  ): Promise<any> {
    this.logger.log('🔍 Validando usuário autenticado via Google...');

    if (!profile || !accessToken) {
      console.log('❌ Falha na autenticação do Google!');
      return done(new Error('Falha na autenticação do Google'), false);
    }

    const { name, emails, photos } = profile;

    const user = {
      email: emails[0].value,
      name: name.givenName,
      picture: photos[0].value,
      accessToken,
    };

    this.logger.log(`👤 Usuário autenticado: ${user.name} (${user.email})`);
    this.logger.log(`📸 Foto do usuário: ${user.picture}`);

    done(null, user);

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
