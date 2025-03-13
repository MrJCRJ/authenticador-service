// /src/auth/auth.service.ts

// Importa o decorador `Injectable` do pacote @nestjs/common.
// `Injectable` é usado para definir uma classe como um provedor (service) no NestJS,
// permitindo que ela seja injetada em outras classes, como controladores ou outros serviços.
import { Injectable } from '@nestjs/common';

// Define a classe `AuthService` como um serviço usando o decorador @Injectable.
// Isso permite que o NestJS gerencie a instância desta classe e a injete onde for necessário.
@Injectable()
export class AuthService {
  /**
   * Método para validar um usuário.
   * Este método pode ser usado para autenticar um usuário e, opcionalmente, salvar suas informações no banco de dados.
   *
   * @param user - O objeto do usuário que precisa ser validado.
   * @returns O mesmo objeto do usuário, indicando que a validação foi bem-sucedida.
   */
  validateUser(user: any): any {
    // Exibe uma mensagem no console para fins de depuração.
    // Em um ambiente de produção, evite usar console.log e utilize um logger apropriado.
    console.log('Usuário autenticado:', user);

    // Retorna o objeto do usuário. Em um cenário real, você pode realizar operações adicionais,
    // como salvar o usuário no banco de dados ou adicionar lógica de negócio aqui.
    return user;
  }
}
