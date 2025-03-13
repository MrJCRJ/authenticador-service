// src/app.controller.ts

// Importa o decorador `Controller` e `Get` do pacote @nestjs/common.
// `Controller` é usado para definir uma classe como um controlador no NestJS.
// `Get` é um decorador que define um método para lidar com requisições HTTP GET.
import { Controller, Get } from '@nestjs/common';

// Define a classe `AppController` como um controlador usando o decorador @Controller.
// O decorador @Controller pode receber um prefixo de rota como argumento (por exemplo, @Controller('api')).
// Se nenhum prefixo for fornecido, as rotas definidas neste controlador serão acessíveis a partir da raiz da aplicação.
@Controller()
export class AppController {
  // Define um método para lidar com requisições HTTP GET na rota raiz ('/').
  // O decorador @Get() pode receber um caminho específico como argumento (por exemplo, @Get('hello')).
  // Se nenhum caminho for fornecido, ele responde à rota raiz.
  @Get()
  getHello(): string {
    // Retorna uma string simples como resposta para a requisição GET.
    return 'Hello World!';
  }
}
