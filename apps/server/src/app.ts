import Fastify from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';

export function buildApp(logStream?: { write(line: string): void }) {
  const app = Fastify({
    // Small default; raise it per route when a route needs more.
    bodyLimit: 16 * 1024,
    logger: {
      level: 'info',
      ...(logStream ? { stream: logStream } : {}),
      // Allow-list: log only method, path (no query string) and id. Never headers or bodies.
      serializers: {
        req: (r) => ({ method: r.method, url: (r.url ?? '').split('?')[0] ?? '', id: r.id }),
      },
      redact: {
        paths: ['req.headers', 'res.headers', '*.password', '*.opaqueRecord', '*.blob', '*.token'],
        censor: '[redacted]',
      },
    },
  });
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);

  // The default 404 handler logs "Route <method>:<full url with query> not found".
  app.setNotFoundHandler((_req, reply) => reply.code(404).send({ error: 'not_found' }));

  app.get('/api/v1/health', () => ({ status: 'ok' }));

  return app;
}
