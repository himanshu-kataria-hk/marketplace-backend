import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PrismaModule } from 'src/prisma/prisma.module';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports: [PrismaModule, JwtModule.register({
    secret: "5918fe8f1611f7b752b73d1f8b4eae18ad7652c3d336697e557e77b9f9231b76",
    signOptions: {expiresIn: '7d'}
  })],
  controllers: [AuthController],
  providers: [AuthService]
})
export class AuthModule {}
