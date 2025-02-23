import { Injectable, ConflictException, UnauthorizedException, Logger } from '@nestjs/common';
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

  async createAccount(email: string, password: string) {
    // Check if account already exists
    const existingAccount = await this.accountRepository.findOne({ where: { email } });
    if (existingAccount) {
      throw new ConflictException('Email already in use');
    }

    // Hash password before storing
    const hashedPassword = await this.hashPassword(password);
    const account = this.accountRepository.create({ email, password: hashedPassword });
    await this.accountRepository.save(account);
    const tokens = this.generateTokens(account.id, account.email);

    return {
      message: "User registered successfully",
      ...tokens
    }
  }

  

  //#region login
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
    return this.generateTokens(account.id, account.email);
  }
  async hashPassword(password: string): Promise<string> {
    return await bcrypt.hash(password, 10);
  }
  async comparePasswords(password: string, hashed: string): Promise<boolean> {
    return await bcrypt.compare(password, hashed);
  }
  //#endregion
  //#region tokens
  async refreshAccessToken(userId: string, refreshToken: string) {
    const account = await this.accountRepository.findOne({ where: { id: userId } });
    if (!account || !account.refreshToken) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const isTokenValid = await bcrypt.compare(refreshToken, account.refreshToken);
    if (!isTokenValid) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    return this.generateTokens(account.id, account.email);
  }
  generateTokens(userId: string, email: string) {
    const payload = { sub: userId, email };

    const accessToken = this.jwtService.sign(payload, { expiresIn: '3h' });  // Access Token (15 mins)
    const refreshToken = this.jwtService.sign(payload, { expiresIn: '7d' });   // Refresh Token (7 days)

    this.storeRefreshToken(userId, refreshToken);
    return {
      accessToken,
      refreshToken
    };
  }
  async storeRefreshToken(userId: string, refreshToken: string) {
    const hashedToken = await bcrypt.hash(refreshToken, 10);
    await this.accountRepository.update(userId, { refreshToken: hashedToken });
  }
  async validateToken(token: string, refreshToken: string) {
    try {
      const verify = this.jwtService.verify(token); // If valid, return decoded payload
      return {
        accountId: verify.sub
      }
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        // If access token is expired, refresh it
        Logger.log("Expired token", "validate token")
        return this.handleTokenRefresh(refreshToken);
      }
      throw new UnauthorizedException('Invalid token');
    }
  }
  async handleTokenRefresh(refreshToken: string) {
    try {
      // Decode the refresh token manually
      const decoded = this.jwtService.decode(refreshToken) as { sub: string; email: string };

      if (!decoded || !decoded.sub) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      // Find the user and validate the refresh token
      return this.refreshAccessToken(decoded.sub, refreshToken);
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  //#endregion
}
