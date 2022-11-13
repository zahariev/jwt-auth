import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import Joi from 'joi';
import { AuthModule } from './auth/auth.module';
import { AtGuard } from './auth/common/guards';
import { PrismaModule } from './prisma/prisma.module';

@Module({
  providers: [
    {
      provide: APP_GUARD,
      useClass: AtGuard,
    },
  ],
  imports: [
    AuthModule,
    PrismaModule,
    ConfigModule.forRoot({
      isGlobal: true,
      validationSchema: Joi.object({
        DATABASE_URL: Joi.string().required(),
        JWT_SECRET: Joi.string().required(),
        AT_SECRET: Joi.string().required(),
        RT_SECRET: Joi.string().required(),
      }),
    }),
  ],
})
export class AppModule {}