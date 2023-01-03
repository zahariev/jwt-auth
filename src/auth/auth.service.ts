import { ConfigService } from '@nestjs/config';
import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto, GoogleUserDto } from './dto';
import * as argon from 'argon2';
import { Tokens } from './types';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { OAuth2Client } from 'google-auth-library';
import { google } from 'googleapis';

@Injectable()
export class AuthService {
    private oauthClient = new OAuth2Client();

    constructor(
        private prisma: PrismaService,
        private jwt: JwtService,
        private config: ConfigService,
    ) {
        const clientId = this.config.get<string>('GOOGLE_CLIENT_ID');
        const clientSecret = this.config.get<string>('GOOGLE_SECRET');
        const redirectUrl = this.config.get<string>('REDIRECT_URL');
        this.oauthClient = new OAuth2Client(clientId, clientSecret, redirectUrl);
        this.oauthClient.on('tokens', (tokens) => {
            console.info('token event:');
            console.info(tokens);
        });
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
        console.log(dto.email);

        const user = await this.prisma.user.findFirst({
            where: {
                email: dto.email,
                active: true,
            },
        });
        if (!user || !user.hash) {
            throw new ForbiddenException('Invalid credentials');
        }

        console.log(user);

        const isMatch = await argon.verify(user.hash, dto.password || '');
        if (!isMatch) {
            throw new ForbiddenException('Invalid credentials');
        }
        const tokens = await this.getTokens(user.id, user.email);
        await this.updateRtHash(user.id, tokens.refresh_token);

        return tokens;
    }

    async googleLogin(req) {
        if (!req.user) {
            return 'No user from google';
        }

        return {
            message: 'User information from google',
            user: req.user,
        };
    }

    async loginGoogleUser(data: GoogleUserDto, ip: string): Promise<Tokens> {
        const tokenInfo = await this.oauthClient.verifyIdToken({ idToken: data.idToken });
        const userInfo = tokenInfo.getPayload();
        console.log(userInfo);

        const user = await this.prisma.user.findUnique({
            where: {
                email: userInfo.email,
            },
        });

        if (!user) {
            //|| !user.active) {
            throw new ForbiddenException('Invalid credentials');
        }

        const tokens = await this.getTokens(user.id, user.email, 'google');
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

    async getTokens(userId: number, email: string, type?: string): Promise<Tokens> {
        const payload = { sub: userId, email, type };

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