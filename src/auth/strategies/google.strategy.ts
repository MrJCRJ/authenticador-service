// /src/auth/strategies/google.strategy.ts

// Importa o decorador `Injectable` do pacote @nestjs/common, que permite que a classe seja injetada como um provedor.
import { Injectable } from '@nestjs/common';

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
  constructor() {
    // Chama o construtor da classe pai (`PassportStrategy`) para configurar a estratégia do Google.
    super({
      clientID: process.env.GOOGLE_CLIENT_ID, // ID do cliente Google (obtido do ambiente).
      clientSecret: process.env.GOOGLE_CLIENT_SECRET, // Segredo do cliente Google (obtido do ambiente).
      callbackURL: process.env.GOOGLE_CALLBACK_URL, // URL de callback após a autenticação no Google.
      scope: ['email', 'profile'], // Escopos solicitados ao Google (email e perfil do usuário).
    });
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
    // Extrai informações relevantes do perfil do usuário.
    const { name, emails, photos } = profile;

    // Cria um objeto de usuário com os dados necessários.
    const user = {
      email: emails[0].value, // E-mail do usuário.
      name: name.givenName, // Nome do usuário.
      picture: photos[0].value, // URL da foto do usuário.
      accessToken, // Token de acesso gerado pelo Google.
    };

    // Chama a função de callback `done` para retornar os dados do usuário ao controlador.
    done(null, user);
  }
}
