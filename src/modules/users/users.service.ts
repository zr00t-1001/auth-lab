import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './users.entity';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly usersRepository: Repository<User>,
  ) { }

  private normalizeEmail(email: string): string {
    return email.toLowerCase().trim();
  }

  async create(dto: CreateUserDto): Promise<User> {
    const user = this.usersRepository.create({
      email: this.normalizeEmail(dto.email),
      passwordHash: dto.passwordHash,
      ...(dto.role ? { role: dto.role } : {}),
    });

    return this.usersRepository.save(user);
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.usersRepository.findOne({
      where: { email: this.normalizeEmail(email) },
    });
  }

  async findById(id: string): Promise<User | null> {
    return this.usersRepository.findOne({
      where: { id },
    });
  }

  async update(id: string, fields: UpdateUserDto): Promise<void> {
    await this.usersRepository.update({ id }, fields);
  }
}