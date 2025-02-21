import { Controller, Logger } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { AuthService } from './auth.service';

@Controller()
export class AuthController {
  constructor(private authService: AuthService,) { }
  private readonly logger = new Logger(AuthController.name)
  // @MessagePattern({ cmd: 'login' })
  // async login(data: { email: string; password: string }) {
  //   const user = await this.authService.validateUser(data.email, data.password);
  //   return this.authService.login(user);
  // }
  @MessagePattern({ cmd: 'register' })
  async register(@Payload() payload: { email: string; password: string }) {
    try {
      return await this.authService.createAccount(payload.email, payload.password);
    }
    catch (e) {
      Logger.error(e);
    }
  }
  @MessagePattern({ cmd: 'login' })
  async login(@Payload() payload: { email: string; password: string }) {
    try {
      return await this.authService.validateAccount(payload.email, payload.password);
    }
    catch (e) {
      return e
    }
  }

  @MessagePattern({cmd: 'validate_token'})
  async validateToken(@Payload() payload: { token: string, refreshToken: string }) {
    try {
      return await this.authService.validateToken(payload.token, payload.refreshToken);
    }
    catch (e) {
      return e
    }
  }
}
