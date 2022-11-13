import { ExtractJwt, Strategy } from 'passport-jwt';
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { env } from 'process';
import { Request } from 'express';

@Injectable()
export class RtStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: env.RT_SECRET,
      passReqToCallback: true,
    });
  }

  async validate(
    req: Request,
    payload: { sub: number; email: string },
  ): Promise<any> {
    const refreshToken = req
      ?.get('authorization')
      ?.replace('Bearer ', '')
      .trim();
    return { ...payload, refreshToken };
  }
}