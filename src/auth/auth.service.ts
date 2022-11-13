import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { Tokens } from './types';
import { env } from 'process';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwt: JwtService) {}

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

  async getTokens(userId: number, email: string): Promise<Tokens> {
    const payload = { sub: userId, email };

    const [at, rt] = await Promise.all([
      await this.jwt.signAsync(payload, {
        expiresIn: '15m',
        secret: env.JWT_SECRET,
      }),
      await this.jwt.signAsync(payload, {
        expiresIn: '135m',
        secret: env.JWT_SECRET,
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