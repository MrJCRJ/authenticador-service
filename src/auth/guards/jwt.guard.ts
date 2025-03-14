// src/auth/guards/jwt.guard.ts
import { Injectable, ExecutionContext, Logger } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtGuard extends AuthGuard('jwt') {
  // Logger personalizado para o JwtGuard, com um toque divertido!
  private readonly logger = new Logger(JwtGuard.name);

  canActivate(context: ExecutionContext) {
    // Obtém o objeto de requisição HTTP do contexto.
    const request = context.switchToHttp().getRequest();

    // Log divertido: mostra todos os cookies recebidos na requisição.
    this.logger.log(`🍪 Cookies recebidos: ${JSON.stringify(request.cookies)}`);

    // Tenta obter o token JWT de duas fontes:
    // 1. Parâmetro de consulta (query parameter) da URL.
    // 2. Cookie 'jwt' da requisição.
    const tokenFromUrl = request.query.token; // Token da URL.
    const tokenFromCookie = request.cookies?.jwt; // Token do cookie.

    // Prioriza o token da URL, caso exista. Caso contrário, usa o token do cookie.
    const token = tokenFromUrl || tokenFromCookie;

    // Log intuitivo: verifica se um token foi encontrado.
    this.logger.log(
      `🔍 Token JWT encontrado? ${!!token ? 'Sim! 🎉' : 'Não... 😢'}`,
    );

    if (token) {
      // Validação básica do token: verifica se é uma string não vazia.
      // Sugestão de melhoria: Adicionar validação do formato do token JWT (header.payload.signature).
      if (typeof token !== 'string' || token.trim() === '') {
        this.logger.error(
          '❌ Token JWT inválido: o token está vazio ou não é uma string válida.',
        );
        return false; // Impede a ativação do guard se o token for inválido.
      }

      // Log divertido: exibe o token JWT extraído.
      this.logger.log(`🔑 Token JWT extraído: ${token}`);

      // Define o token no cabeçalho 'Authorization' no formato 'Bearer <token>'.
      request.headers['authorization'] = `Bearer ${token}`;

      // Log intuitivo: confirma que o token foi adicionado ao cabeçalho.
      this.logger.log(
        `📤 Token JWT adicionado ao cabeçalho 'Authorization': Bearer ${token}`,
      );
    } else {
      // Log de aviso: nenhum token JWT foi encontrado.
      this.logger.warn('⚠️ Nenhum token JWT encontrado na URL ou nos cookies.');
    }

    // Chama o método canActivate da classe pai (AuthGuard) para continuar o processo de autenticação.
    return super.canActivate(context);
  }
}

/** Sugestões de Melhorias Incorporadas como Comentários:
//
Validação do Formato do Token JWT:

Adicione uma validação para garantir que o token está no formato correto (header.payload.signature).

typescript
Copy
// Sugestão de melhoria: Adicionar validação do formato do token JWT.
const tokenParts = token.split('.');
if (tokenParts.length !== 3) {
  this.logger.error('❌ Token JWT inválido: o token não está no formato esperado (header.payload.signature).');
  return false;
}
Suporte a Múltiplas Fontes de Token:

Adicione suporte para tokens enviados no corpo da requisição (body) ou em cabeçalhos personalizados.

typescript
Copy
// Sugestão de melhoria: Adicionar suporte para tokens no corpo da requisição ou em cabeçalhos personalizados.
const tokenFromBody = request.body?.token;
const tokenFromHeader = request.headers['x-custom-token'];
const token = tokenFromUrl || tokenFromCookie || tokenFromBody || tokenFromHeader;
Logs Estruturados:

Use logs estruturados para facilitar a análise em ferramentas de monitoramento.

typescript
Copy
// Sugestão de melhoria: Usar logs estruturados para melhorar a análise.
this.logger.log({
  message: 'Token JWT extraído',
  token: token,
  source: tokenFromUrl ? 'URL' : tokenFromCookie ? 'Cookie' : 'Outro',
});
Tratamento de Erros:

Adicione um bloco try-catch para capturar e tratar possíveis erros durante a execução do método canActivate.

typescript
Copy
// Sugestão de melhoria: Adicionar tratamento de erros.
try {
  return super.canActivate(context);
} catch (error) {
  this.logger.error(`💥 Erro durante a ativação do guard: ${error.message}`);
  return false;
}
Configuração Dinâmica:

Permita que a chave do cookie (atualmente jwt) seja configurável via variáveis de ambiente.

typescript
Copy
// Sugestão de melhoria: Tornar a chave do cookie configurável.
const cookieKey = process.env.JWT_COOKIE_KEY || 'jwt';
const tokenFromCookie = request.cookies?.[cookieKey];
Cache de Tokens:

Implemente um cache de tokens válidos para melhorar o desempenho.

typescript
Copy
// Sugestão de melhoria: Implementar cache de tokens válidos.
if (this.tokenCache.has(token)) {
  return true; // Token já validado e cacheado.
}
Documentação:

Adicione uma documentação clara usando JSDoc.

typescript
Copy
/**
 * Guard para autenticação JWT.
 * Este guard extrai o token JWT da URL, cookies ou outras fontes e o adiciona ao cabeçalho 'Authorization'.

@Injectable()
export class JwtGuard extends AuthGuard('jwt') {
  // ...
}
Testes Automatizados:

Escreva testes unitários e de integração para garantir que o guard funcione corretamente.

typescript
Copy
// Sugestão de melhoria: Escrever testes automatizados para diferentes cenários.
// Exemplo: Testar com token válido, token inválido, token ausente, etc.
Segurança Adicional:

Adicione verificações de expiração do token e validação da assinatura.

typescript
Copy
// Sugestão de melhoria: Validar expiração e assinatura do token.
const decodedToken = jwt.decode(token, { complete: true });
if (decodedToken.payload.exp < Date.now() / 1000) {
  this.logger.error('❌ Token JWT expirado.');
  return false;
}
Refatoração para Reutilização:

Extraia a lógica de extração e validação do token para um serviço separado.

typescript
Copy
// Sugestão de melhoria: Extrair lógica de token para um serviço reutilizável.
const tokenService = new TokenService();
const token = tokenService.extractToken(request);
*/
