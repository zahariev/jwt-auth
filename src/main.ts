import { INestApplication, ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { AppModule } from './app.module';

async function bootstrap() {
    const app = await NestFactory.create(AppModule);
    const configService = app.get(ConfigService);
    cors(app, configService);

    initSwagger(app);

    app.setGlobalPrefix('api');
    app.useGlobalPipes(
        new ValidationPipe({
            whitelist: true,
            transform: true,
            // forbidNonWhitelisted: true,
            disableErrorMessages: process.env.NODE_ENV === 'PRODUCTION' ? true : false,
        }),
    );
    await app.listen(3003);
}
bootstrap();

function cors(app: INestApplication, configService: ConfigService) {
    if (configService.get('isDevelopmentEnv')) {
        const options = {
            origin: '*',
            methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
            preflightContinue: false,
            optionsSuccessStatus: 204,
            credentials: true,
        };
        app.enableCors(options);
    }
}

function initSwagger(app: INestApplication) {
    const config = new DocumentBuilder()
        .setTitle('POS-BE Swagger API')
        .setDescription('POS-BE Swagger API')
        .setVersion('1.0')
        .addBearerAuth({
            description: 'Enter your token',
            name: 'Authorization',
            bearerFormat: 'Bearer ',
            scheme: 'Bearer',
            type: 'http',
            in: 'Header',
        })
        .build();

    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('swagger', app, document);
}