import { Injectable, ConflictException, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';

import { Account } from './account.entity';
@Injectable()
export class AuthService {
  constructor(private jwtService: JwtService,
    @InjectRepository(Account)
    private accountRepository: Repository<Account>) { }

  // async validateUser(email: string, password: string): Promise<any> {
  //   // Here, we’ll later fetch user data from `users-service` (mocked for now)
  //   const mockUser = { id: 1, email: 'test@example.com', password: 'password' };

  //   if (email === mockUser.email && password === mockUser.password) {
  //     return { id: mockUser.id, email: mockUser.email };
  //   }
  //   throw new UnauthorizedException('Invalid credentials');
  // }

  async createAccount(email: string, password: string) {
    // Check if account already exists
    const existingAccount = await this.accountRepository.findOne({ where: { email } });
    if (existingAccount) {
      throw new ConflictException('Email already in use');
    }

    // Hash password before storing
    const hashedPassword = await this.hashPassword(password);
    const account = this.accountRepository.create({ email, password: hashedPassword });

    return this.accountRepository.save(account);
  }

  async validateAccount(email: string, password: string) {
    const account = await this.accountRepository.findOne({ where: { email } });
    if (!account) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Compare password with hashed password
    const isPasswordValid = await bcrypt.compare(password, account.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    return { message: 'Authentication successful' };
  }
  async login(user: any) {
    const payload = { email: user.email, sub: user.id };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }
  async hashPassword(password: string): Promise<string> {
    return await bcrypt.hash(password, 10);
  }

  async comparePasswords(password: string, hashed: string): Promise<boolean> {
    return await bcrypt.compare(password, hashed);
  }

  generateAccessToken(payload: any) {
    return this.jwtService.sign(payload);
  }

  generateRefreshToken(payload: any) {
    return this.jwtService.sign(payload, { expiresIn: '7d' });
  }

  async validateToken(token: string) {
    try {
      return this.jwtService.verify(token);
    } catch (error) {
      throw new UnauthorizedException('Invalid token');
    }
  }
}
