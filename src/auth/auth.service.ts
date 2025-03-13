import { Injectable } from '@nestjs/common';

@Injectable()
export class AuthService {
  validateUser(user: any) {
    // Aqui você pode salvar o usuário no banco se precisar
    console.log('Usuário autenticado:', user);
    return user;
  }
}
