// src/common/services/prometheus.service.ts
import { Injectable } from '@nestjs/common';
import { Counter, Histogram, Gauge, Registry } from 'prom-client';

@Injectable()
export class PrometheusService {
  public readonly httpRequestCounter: Counter<string>;
  public readonly httpRequestDuration: Histogram<string>;
  public readonly memoryUsageGauge: Gauge<string>;

  constructor() {
    const registry = new Registry();
    registry.setDefaultLabels({
      app: 'authenticator-service',
    });

    this.httpRequestCounter = new Counter({
      name: 'http_requests_total',
      help: 'Total de requisições HTTP',
      labelNames: ['method', 'route', 'status'],
      registers: [registry],
    });

    this.httpRequestDuration = new Histogram({
      name: 'http_request_duration_seconds',
      help: 'Duração das requisições HTTP em segundos',
      labelNames: ['method', 'route', 'status'],
      buckets: [0.1, 0.5, 1, 2, 5],
      registers: [registry],
    });

    this.memoryUsageGauge = new Gauge({
      name: 'nodejs_memory_usage_bytes',
      help: 'Uso de memória da aplicação',
      labelNames: ['type'],
      registers: [registry],
    });

    this.startCollection();
  }

  private startCollection() {
    const collectDefaultMetrics = require('prom-client').collectDefaultMetrics;
    collectDefaultMetrics();

    setInterval(() => {
      const memoryUsage = process.memoryUsage();
      for (const [key, value] of Object.entries(memoryUsage)) {
        this.memoryUsageGauge.set({ type: key }, value);
      }
    }, 5000);
  }
}
