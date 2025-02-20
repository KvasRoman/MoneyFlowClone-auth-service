import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { TypeOrmModule } from '@nestjs/typeorm';
@Module({
  imports: [
    AuthModule,
    TypeOrmModule.forRoot({
      type: 'mysql',
      host: 'localhost',
      port: 3306,
      username: 'root',
      password: '1234',
      database: 'test_db',
      autoLoadEntities: true, // Automatically load entities
      synchronize: true, // Use only in development (drops and recreates tables)
    }),
  ],
})
export class AppModule {}
