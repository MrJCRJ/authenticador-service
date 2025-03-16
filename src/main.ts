// src/main.ts

// Importa a função NestFactory do pacote @nestjs/core, que é usada para criar uma instância da aplicação NestJS.
import { NestFactory } from '@nestjs/core';

// Importa o módulo principal da aplicação, que contém todos os controladores, provedores e outros módulos.
import { AppModule } from './app.module';

// Importa o cookie-parser para manipulação de cookies.
import cookieParser from 'cookie-parser';

// Importa o Logger do NestJS para logs personalizados.
import { Logger } from '@nestjs/common';

// Função assíncrona que inicializa a aplicação.
async function bootstrap() {
  // Cria uma instância da aplicação NestJS usando o módulo principal (AppModule).
  const app = await NestFactory.create(AppModule);

  // Logger personalizado para o bootstrap, com emojis para logs divertidos e intuitivos 🎉
  const logger = new Logger('Bootstrap');

  // Middleware para manipulação de cookies.
  app.use(cookieParser());
  logger.log('🍪 Cookie-parser configurado com sucesso!');

  // Habilita o CORS (Cross-Origin Resource Sharing) para permitir requisições de diferentes origens.
  app.enableCors({
    origin: process.env.FRONTEND_URL || 'http://localhost:5500', // Permite requisições do frontend.
    credentials: true, // Permite o envio de cookies e headers de autenticação.
  });
  logger.log('🌍 CORS configurado com sucesso!');

  // Inicia o servidor HTTP e faz com que a aplicação escute na porta especificada.
  // A porta é obtida a partir da variável de ambiente PORT, ou usa 3000 como padrão caso PORT não esteja definida.
  const port = process.env.PORT || 3000;
  await app.listen(port);

  // Exibe uma mensagem no console indicando que a aplicação está rodando e em qual porta.
  logger.log(`🚀 Aplicação rodando em: ${await app.getUrl()}`);
}

// Chama a função bootstrap para iniciar a aplicação.
bootstrap().catch((error) => {
  // Log de erro caso ocorra algum problema durante a inicialização.
  const logger = new Logger('Bootstrap');
  logger.error(`💥 Falha ao iniciar a aplicação: ${error.message}`);
  process.exit(1); // Encerra o processo com código de erro.
});

/**Sugestões de Melhoria (Para Implementar):
Configuração Dinâmica:

Use o ConfigService para carregar configurações dinamicamente (por exemplo, porta, URL do frontend).

typescript
Copy
const configService = app.get(ConfigService);
const port = configService.get<number>('PORT', 3000);
const frontendUrl = configService.get<string>('FRONTEND_URL', 'http://localhost:3000');
Documentação com Swagger:

Adicione o SwaggerModule para documentar a API.

typescript
Copy
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';

const config = new DocumentBuilder()
  .setTitle('API Documentation')
  .setDescription('Descrição da API')
  .setVersion('1.0')
  .build();
const document = SwaggerModule.createDocument(app, config);
SwaggerModule.setup('api', app, document);
Segurança Adicional:

Adicione middlewares de segurança, como helmet e rate-limiting.

typescript
Copy
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

app.use(helmet());
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 100, // Limite de 100 requisições por IP
  }),
);
Monitoramento:

Adicione suporte para ferramentas de monitoramento (por exemplo, Prometheus).

typescript
Copy
import { PrometheusModule } from '@willsoto/nestjs-prometheus';

app.use('/metrics', PrometheusModule.createHandler());
Testes Automatizados:

Adicione testes de integração para garantir que a aplicação inicialize corretamente.

typescript
Copy
describe('Bootstrap', () => {
  it('deve iniciar a aplicação sem erros', async () => {
    await expect(bootstrap()).resolves.not.toThrow();
  });
});
Logs Estruturados:

Use logs estruturados (em formato JSON) para facilitar a análise em ferramentas de monitoramento.

typescript
Copy
logger.log({
  message: 'Aplicação iniciada com sucesso',
  port,
  url: await app.getUrl(),
});
Exemplo de Saída de Logs:
Copy
🍪 Cookie-parser configurado com sucesso!
🌍 CORS configurado com sucesso!
🚀 Aplicação rodando em: http://localhost:3000 */
