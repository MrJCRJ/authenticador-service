// src/app.controller.ts

// Importa o decorador `Controller` e `Get` do pacote @nestjs/common.
// `Controller` é usado para definir uma classe como um controlador no NestJS.
// `Get` é um decorador que define um método para lidar com requisições HTTP GET.
import { Controller, Get, Logger } from '@nestjs/common';

// Define a classe `AppController` como um controlador usando o decorador @Controller.
// O decorador @Controller pode receber um prefixo de rota como argumento (por exemplo, @Controller('api')).
// Se nenhum prefixo for fornecido, as rotas definidas neste controlador serão acessíveis a partir da raiz da aplicação.
@Controller()
export class AppController {
  // Logger personalizado para o AppController, com emojis para logs divertidos e intuitivos 🎉
  private readonly logger = new Logger(AppController.name);

  /**
   * Rota raiz da aplicação.
   * Responde a requisições HTTP GET na rota '/' com uma mensagem de boas-vindas.
   *
   * @returns Uma string simples com a mensagem "Hello World!".
   */
  @Get()
  getHello(): string {
    // Log intuitivo: requisição recebida na rota raiz.
    this.logger.log('🌍 Requisição GET recebida na rota raiz.');

    // Retorna uma string simples como resposta para a requisição GET.
    return 'Hello World!';
  }
}

/**Sugestões de Melhoria (Para Implementar):
Rota de Status da Aplicação:

Adicione uma rota para verificar o status da aplicação (health check).

typescript
Copy
@Get('status')
getStatus(): { status: string } {
  this.logger.log('🩺 Verificando status da aplicação...');
  return { status: 'up' };
}
Documentação com Swagger:

Adicione anotações do Swagger para documentar a API.

typescript
Copy
import { ApiOperation, ApiResponse } from '@nestjs/swagger';

@Get()
@ApiOperation({ summary: 'Retorna uma mensagem de boas-vindas' })
@ApiResponse({ status: 200, description: 'Mensagem de boas-vindas' })
getHello(): string {
  return 'Hello World!';
}
Tratamento de Erros:

Adicione um bloco try-catch para capturar e tratar possíveis erros.

typescript
Copy
@Get()
getHello(): string {
  try {
    this.logger.log('🌍 Requisição GET recebida na rota raiz.');
    return 'Hello World!';
  } catch (error) {
    this.logger.error(`💥 Erro ao processar requisição: ${error.message}`);
    throw error;
  }
}
Configuração Dinâmica:

Use o ConfigService para carregar mensagens dinamicamente.

typescript
Copy
constructor(private readonly configService: ConfigService) {}

@Get()
getHello(): string {
  return this.configService.get<string>('WELCOME_MESSAGE', 'Hello World!');
}
Testes Automatizados:

Adicione testes unitários para garantir que o controlador funcione corretamente.

typescript
Copy
describe('AppController', () => {
  let appController: AppController;

  beforeEach(() => {
    appController = new AppController();
  });

  it('deve retornar "Hello World!"', () => {
    expect(appController.getHello()).toBe('Hello World!');
  });
});
Segurança:

Adicione proteção contra ataques comuns (por exemplo, rate limiting).

typescript
Copy
import { Throttle } from '@nestjs/throttler';

@Throttle({ default: { limit: 10, ttl: 60 } }) // Limita a 10 requisições por minuto.
@Get()
getHello(): string {
  return 'Hello World!';
}
Exemplo de Saída de Logs:
Copy
🌍 Requisição GET recebida na rota raiz. */
