// src/auth/auth.service.ts
import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(private readonly jwtService: JwtService) {}

  generateToken(user: any): string {
    const payload = { email: user.email, sub: user.name };
    return this.jwtService.sign(payload);
  }

  validateToken(token: string): any {
    try {
      return this.jwtService.verify(token);
    } catch (error) {
      return null; // Token inválido ou expirado.
    }
  }
}
