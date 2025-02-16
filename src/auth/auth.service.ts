import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(private jwtService: JwtService) {}

  async validateUser(email: string, password: string): Promise<any> {
    // Here, we’ll later fetch user data from `users-service` (mocked for now)
    const mockUser = { id: 1, email: 'test@example.com', password: 'password' };

    if (email === mockUser.email && password === mockUser.password) {
      return { id: mockUser.id, email: mockUser.email };
    }
    throw new UnauthorizedException('Invalid credentials');
  }

  async login(user: any) {
    const payload = { email: user.email, sub: user.id };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }
}
