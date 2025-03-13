// src/app.module.ts

import { Module } from '@nestjs/common';
import { AppController } from './app.controller'; // Importe o controlador

@Module({
  imports: [],
  controllers: [AppController], // Adicione o controlador à lista de controladores
  providers: [],
})
export class AppModule {}
