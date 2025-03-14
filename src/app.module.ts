// src/app.module.ts

// Importa o decorador `Module` do pacote @nestjs/common, que é usado para definir um módulo no NestJS.
import { Module } from '@nestjs/common';

// Importa o controlador principal da aplicação.
import { AppController } from './app.controller';

// Importa o módulo de autenticação, que contém controladores, provedores e outros componentes relacionados à autenticação.
import { AuthModule } from './auth/auth.module';

import { ConfigModule } from '@nestjs/config';

// Define o módulo principal da aplicação usando o decorador @Module.
@Module({
  // A lista de módulos importados. Neste caso, estamos importando o AuthModule,
  // que pode conter funcionalidades relacionadas à autenticação e autorização.
  imports: [AuthModule, ConfigModule.forRoot({ isGlobal: true })],

  // A lista de controladores que pertencem a este módulo.
  // O AppController é o controlador principal da aplicação, que lida com as rotas raiz.
  controllers: [AppController],

  // A lista de provedores (services, repositories, etc.) que pertencem a este módulo.
  // Neste caso, não há provedores definidos no módulo principal.
  providers: [],
})
// Exporta a classe AppModule, que representa o módulo principal da aplicação.
export class AppModule {}
