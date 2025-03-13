// src/app.module.ts

import { Module } from '@nestjs/common';
import { AppController } from './app.controller'; // Importe o controlador
import { AuthModule } from './auth/auth.module';

@Module({
  imports: [AuthModule],
  controllers: [AppController], // Adicione o controlador à lista de controladores
  providers: [],
})
export class AppModule {}
