import { Test, TestingModule } from '@nestjs/testing';
import { AppController } from './app.controller';

describe('AppController', () => {
  let controller: AppController;

  beforeEach(async () => {
    const moduleRef: TestingModule = await Test.createTestingModule({
      controllers: [AppController],
    }).compile();
    controller = moduleRef.get<AppController>(AppController);
  });

  it('health() reports ok', () => {
    const res = controller.health();
    expect(res.status).toBe('ok');
    expect(typeof res.uptime).toBe('number');
    expect(typeof res.timestamp).toBe('string');
  });
});