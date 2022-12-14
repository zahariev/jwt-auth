import { RtStrategy, AtStrategy } from './strategies';
import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { GoogleStrategy } from './strategies/google.strategy';

@Module({
    imports: [JwtModule],
    providers: [AuthService, AtStrategy, RtStrategy, GoogleStrategy],
    controllers: [AuthController],
})
export class AuthModule {}