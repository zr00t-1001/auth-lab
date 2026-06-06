import { TypeOrmModuleOptions } from '@nestjs/typeorm';

/**
 * DB config from environment, with lab-friendly fallbacks so it still runs
 * locally without a .env. In Docker these come from docker-compose.
 */
export const databaseConfig: TypeOrmModuleOptions = {
  type: 'postgres',
  host: process.env.DB_HOST ?? 'localhost',
  port: Number(process.env.DB_PORT ?? 5432),
  username: process.env.DB_USER ?? 'postgres',
  password: String(process.env.DB_PASS ?? '1234'),
  database: process.env.DB_NAME ?? 'auth_sys',
  autoLoadEntities: true,
  // Auto-create tables. Fine for a lab; set DB_SYNC=false for migrations.
  synchronize: process.env.DB_SYNC !== 'false',
};
