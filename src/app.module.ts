import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { GraphQLModule } from '@nestjs/graphql';
import { ApolloServerPluginLandingPageLocalDefault } from 'apollo-server-core';
import Joi from 'joi';
import { AuthModule } from './auth/auth.module';
import { AtGuard } from './common/guards';
import { PrismaModule } from './prisma/prisma.module';
import { DonationsModule } from './donations/donations.module';
import { ApolloDriver } from '@nestjs/apollo';
import { GraphQLDateTime } from 'graphql-iso-date';
@Module({
    providers: [
        {
            provide: APP_GUARD,
            useClass: AtGuard,
        },
    ],
    imports: [
        AuthModule,
        GraphQLModule.forRoot({
            driver: ApolloDriver,
            typePaths: ['./**/*.graphql'],
            playground: false,
            plugins: [ApolloServerPluginLandingPageLocalDefault()],
            resolvers: { DateTime: GraphQLDateTime },
        }),
        PrismaModule,
        ConfigModule.forRoot({
            isGlobal: true,
            validationSchema: Joi.object({
                DATABASE_URL: Joi.string().required(),
                JWT_SECRET: Joi.string().required(),
                AT_SECRET: Joi.string().required(),
                RT_SECRET: Joi.string().required(),
                GOOGLE_CLIENT_ID: Joi.string().required(),
                GOOGLE_SECRET: Joi.string().required(),
            }),
        }),
        DonationsModule,
    ],
})
export class AppModule {}