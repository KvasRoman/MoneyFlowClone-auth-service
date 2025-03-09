import { Controller, Logger } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { AuthService } from './auth.service';

@Controller()
export class AuthController {
  constructor(private authService: AuthService,) { }
  @MessagePattern({ cmd: 'register' })
  async register(@Payload() payload: { email: string; password: string }) {
      return await this.authService.createAccount(payload.email, payload.password);
  }
  @MessagePattern({ cmd: 'login' })
  async login(@Payload() payload: { email: string; password: string }) {
      return await this.authService.validateAccount(payload.email, payload.password);  
  }

  @MessagePattern({cmd: 'validate_token'})
  async validateToken(@Payload() payload: { token: string, refreshToken: string }) {
      return await this.authService.validateToken(payload.token, payload.refreshToken);
  }
  @MessagePattern({cmd: 'get_email'})
  async getEmail(@Payload() payload: { accountId: string }) {
      return await this.authService.getEmail(payload.accountId);
  }
}
