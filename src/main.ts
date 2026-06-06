import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Trust X-Forwarded-For so the rate limiter and req.ip use the real client
  // IP, not the loopback socket. Without this, every local request (your
  // browser AND the simulator) shares one ::1 rate-limit bucket, so the
  // simulator's victim login gets throttled and no geo session is created.
  // Lab-permissive (trusts any proxy); scope this before a real deployment.
  app.getHttpAdapter().getInstance().set('trust proxy', true);

  // Allow the Astro dev frontend (and other local origins) to call the API.
  // Lab-permissive; tighten the origin list before any real deployment.
  app.enableCors({
    origin: true,
    credentials: true,
  });

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