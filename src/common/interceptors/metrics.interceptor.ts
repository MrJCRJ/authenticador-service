// src/common/interceptors/metrics.interceptor.ts
import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { PrometheusService } from '../services/prometheus.service';

@Injectable()
export class MetricsInterceptor implements NestInterceptor {
  constructor(private readonly prometheusService: PrometheusService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const httpContext = context.switchToHttp();
    const request = httpContext.getRequest();
    const response = httpContext.getResponse();

    const start = Date.now();

    return next.handle().pipe(
      tap(() => {
        const duration = (Date.now() - start) / 1000;
        const status = response.statusCode;
        const route = request.route?.path || request.path;

        this.prometheusService.httpRequestCounter
          .labels({
            method: request.method,
            route,
            status,
          })
          .inc();

        this.prometheusService.httpRequestDuration
          .labels({
            method: request.method,
            route,
            status,
          })
          .observe(duration);
      }),
    );
  }
}
