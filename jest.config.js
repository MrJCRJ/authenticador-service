module.exports = {
  moduleFileExtensions: ['js', 'json', 'ts'],
  rootDir: '.', // A raiz do projeto
  testRegex: 'test/.*\\.spec\\.ts$', // Procura apenas na pasta "test"
  transform: {
    '^.+\\.(t|j)s$': 'ts-jest', // Transformar arquivos TypeScript
  },
  collectCoverageFrom: ['**/*.(t|j)s'], // Coletar cobertura de todos os arquivos TypeScript
  coverageDirectory: '../coverage', // Diretório para relatórios de cobertura
  testEnvironment: 'node', // Ambiente de teste (Node.js)
};