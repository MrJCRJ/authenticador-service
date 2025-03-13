// /src/main.ts

// Importa a função NestFactory do pacote @nestjs/core, que é usada para criar uma instância da aplicação NestJS.
import { NestFactory } from '@nestjs/core';

// Importa o módulo principal da aplicação, que contém todos os controladores, provedores e outros módulos.
import { AppModule } from './app.module';

// Função assíncrona que inicializa a aplicação.
async function bootstrap() {
  // Cria uma instância da aplicação NestJS usando o módulo principal (AppModule).
  const app = await NestFactory.create(AppModule);

  // Inicia o servidor HTTP e faz com que a aplicação escute na porta especificada.
  // A porta é obtida a partir da variável de ambiente PORT, ou usa 3000 como padrão caso PORT não esteja definida.
  await app.listen(process.env.PORT ?? 3000);

  // Exibe uma mensagem no console indicando que a aplicação está rodando e em qual porta.
  console.log(`Application is running on: ${await app.getUrl()}`);
}

// Chama a função bootstrap para iniciar a aplicação.
bootstrap();
