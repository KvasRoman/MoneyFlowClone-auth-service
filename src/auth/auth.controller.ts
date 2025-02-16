import { Controller } from '@nestjs/common';
import { MessagePattern } from '@nestjs/microservices';
import { AuthService } from './auth.service';

@Controller()
export class AuthController {
  constructor(private authService: AuthService) {}

  @MessagePattern({ cmd: 'login' })
  async login(data: { email: string; password: string }) {
    const user = await this.authService.validateUser(data.email, data.password);
    return this.authService.login(user);
  }
}
