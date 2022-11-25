import { ConfigService } from '@nestjs/config';
import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto, GoogleUserDto } from './dto';
import * as argon from 'argon2';
import { Tokens } from './types';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { google } from 'googleapis';

@Injectable()
export class AuthService {
    private oauthClient = new google.auth.OAuth2();

    constructor(
        private prisma: PrismaService,
        private jwt: JwtService,
        private config: ConfigService,
    ) {
        const clientId = this.config.get<string>('GOOGLE_CLIENT_ID');
        const clientSecret = this.config.get<string>('GOOGLE_SECRET');
        this.oauthClient = new google.auth.OAuth2(clientId, clientSecret);
    }

    public async signupLocal(dto: AuthDto): Promise<Tokens> {
        const hash = await argon.hash(dto.password);

        try {
            const newUser = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    hash,
                },
                select: {
                    id: true,
                    email: true,
                    createdAt: true,
                },
            });
            const tokens = await this.getTokens(newUser.id, newUser.email);
            await this.updateRtHash(newUser.id, tokens.refresh_token);
            return tokens;
        } catch (error) {
            if (error instanceof PrismaClientKnownRequestError) {
                if (error.code === 'P2002') {
                    throw new ForbiddenException('User already exists');
                }
            }
        }
    }

    public async signinLocal(dto: AuthDto): Promise<Tokens> {
        const user = await this.prisma.user.findUnique({
            where: {
                email: dto.email,
            },
        });
        if (!user) {
            throw new ForbiddenException('Invalid credentials');
        }
        const isMatch = await argon.verify(user.hash, dto.password);
        if (!isMatch) {
            throw new ForbiddenException('Invalid credentials');
        }
        const tokens = await this.getTokens(user.id, user.email);
        await this.updateRtHash(user.id, tokens.refresh_token);

        return tokens;
    }

    async loginGoogleUser(data: GoogleUserDto, ip: string): Promise<Tokens> {
        // const tokenInfo = await this.oauthClient.getTokenInfo(data.idToken);
        // console.log(tokenInfo);

        const user = await this.prisma.user.findUnique({
            where: {
                email: data.email,
            },
        });

        if (!user) {
            throw new ForbiddenException('Invalid credentials');
        }

        const tokens = await this.getTokens(user.id, user.email, ip);
        await this.updateRtHash(user.id, tokens.refresh_token);

        return tokens;
    }

    public async logout(userId: number) {
        await this.prisma.user.updateMany({
            where: {
                id: userId,
                hashedRt: {
                    not: null,
                },
            },
            data: {
                hashedRt: null,
            },
        });
    }

    async refreshTokens(userId: number, rt: string) {
        const user = await this.prisma.user.findUnique({
            where: {
                id: userId,
            },
        });

        if (!user || !user.hashedRt) {
            throw new ForbiddenException('Invalid credentials');
        }

        const isMatch = await argon.verify(user.hashedRt, rt);
        if (!isMatch) {
            throw new ForbiddenException('Invalid credentials');
        }

        const tokens = await this.getTokens(user.id, user.email);
        await this.updateRtHash(user.id, tokens.refresh_token);

        return tokens;
    }

    async getTokens(userId: number, email: string, ip?: string): Promise<Tokens> {
        const payload = { sub: userId, email, ip };

        const [at, rt] = await Promise.all([
            await this.jwt.signAsync(payload, {
                expiresIn: '15m',
                secret: this.config.get<string>('AT_SECRET'),
            }),
            await this.jwt.signAsync(payload, {
                expiresIn: '1235m',
                secret: this.config.get<string>('RT_SECRET'),
            }),
        ]);

        return { access_token: at, refresh_token: rt };
    }

    async updateRtHash(userId: number, rt: string): Promise<void> {
        const hash = await argon.hash(rt);
        await this.prisma.user.update({
            where: { id: userId },
            data: {
                hashedRt: hash,
            },
        });
    }
}