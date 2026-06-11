import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { loadVaultSecrets } from './vault/vault-secrets';

async function bootstrap() {
  // When USE_VAULT=true, pull secrets from Vault and inject them into the
  // environment BEFORE anything reads it. The Nest module graph evaluates DB and
  // JWT config from env at import time, so AppModule is imported dynamically
  // AFTER this call — otherwise the secrets would arrive too late.
  await loadVaultSecrets();
  const { AppModule } = await import('./app.module.js');

  const app = await NestFactory.create(AppModule);

  // Trust X-Forwarded-For so the rate limiter and req.ip use the real client
  // IP, not the loopback socket. Without this, every local request (your
  // browser AND the simulator) shares one ::1 rate-limit bucket, so the
  // simulator's victim login gets throttled and no geo session is created.
  // Lab-permissive (trusts any proxy); scope this before a real deployment.
  const http = app.getHttpAdapter().getInstance();
  http.set('trust proxy', true);
  http.disable('x-powered-by'); // don't advertise the framework

  // Security headers. Set explicitly (no extra dependency) rather than pulling
  // in helmet. HSTS only takes effect once traffic is HTTPS (browsers ignore
  // it over plain HTTP), so it's safe to send now and active behind the TLS
  // proxy. No CSP here on purpose: this is a JSON API and a strict CSP would
  // break the Swagger UI at /api — CSP belongs on the frontend (nginx) instead.
  app.use((_req: any, res: any, next: any) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    // HSTS is OFF by default. With a local self-signed / Caddy-internal cert,
    // an HSTS pin makes the browser's certificate warning NON-bypassable and
    // locks you out of the site. Enable it (ENABLE_HSTS=true) only when you are
    // serving a trusted certificate (e.g. a real domain via Let's Encrypt).
    if (process.env.ENABLE_HSTS === 'true') {
      res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
    }
    next();
  });

  // CORS: allow only known origins instead of reflecting any. Override in
  // deployment with CORS_ORIGINS="https://app.example.com,https://..." .
  // Defaults cover the local Astro frontend + the API host itself.
  const origins = (
    process.env.CORS_ORIGINS ??
    'http://localhost:4321,http://127.0.0.1:4321,http://localhost:5173,http://localhost:3000'
  )
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean);
  app.enableCors({ origin: origins, credentials: true });

  // Without this, the class-validator decorators on the DTOs are inert.
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: { enableImplicitConversion: true },
    }),
  );

  // Interactive API docs at /api (Bearer auth supported via "Authorize").
  const swaggerConfig = new DocumentBuilder()
    .setTitle('auth-lab API')
    .setDescription('Hardened auth backend: auth, sessions, security events.')
    .setVersion('1.0')
    .addBearerAuth()
    .build();
  SwaggerModule.setup(
    'api',
    app,
    SwaggerModule.createDocument(app, swaggerConfig),
  );

  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
