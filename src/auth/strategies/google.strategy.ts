// src/auth/strategies/google.strategy.ts
import { Injectable, Logger } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-google-oauth20';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';

interface GoogleProfile {
  emails: { value: string }[];
  displayName?: string;
  photos?: { value: string }[];
}

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  private readonly logger = new Logger(GoogleStrategy.name);

  constructor(configService: ConfigService) {
    super({
      clientID: configService.get('GOOGLE_CLIENT_ID'),
      clientSecret: configService.get('GOOGLE_CLIENT_SECRET'),
      callbackURL: configService.get('GOOGLE_CALLBACK_URL'),
      scope: ['email', 'profile'],
      passReqToCallback: true,
    });
  }

  async validate(
    req: Request,
    accessToken: string,
    refreshToken: string,
    profile: any,
  ): Promise<any> {
    const state = req.query.state;
    if (!state) {
      throw new Error('State parameter required');
    }

    return {
      id: profile.id,
      email: profile.emails[0].value,
      name: profile.displayName,
      picture: profile.photos?.[0]?.value,
      locale: profile._json?.locale,
      verified: profile.emails[0].verified,
      accessToken,
      refreshToken,
    };
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
