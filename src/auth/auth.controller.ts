import { AuthService } from './auth.service';
import {
    Body,
    Controller,
    Get,
    HttpCode,
    HttpException,
    HttpStatus,
    Ip,
    Post,
    Req,
    UseGuards,
} from '@nestjs/common';
import { AuthDto, GoogleTokenDto } from './dto';
import { Tokens } from './types';

import { RtGuard } from 'src/common/guards';
import { GetCurrentUser, Public } from 'src/common/decorators';
import { GetCurrentUserId } from 'src/common/decorators/get-current-user-id.decorator';
import { AuthGuard } from '@nestjs/passport';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) {}

    @Public()
    @Post('local/signup')
    @HttpCode(HttpStatus.CREATED)
    async signupLocal(@Body() dto: AuthDto): Promise<Tokens> {
        return this.authService.signupLocal(dto);
    }

    @Public()
    @Post('local/signin')
    @HttpCode(HttpStatus.OK)
    async signinLocal(@Body() dto: AuthDto): Promise<Tokens> {
        return this.authService.signinLocal(dto);
    }

    @Post('logout')
    @HttpCode(HttpStatus.OK)
    logout(@GetCurrentUserId() userId: number) {
        return this.authService.logout(userId);
    }

    // @Post('google/login')
    // async googleLogin(@Body() body: GoogleTokenDto, @Req() req, @Ip() ip: string): Promise<Tokens> {
    //     const result = await this.authService.googleLogin(body.token, {
    //         userAgent: req.headers['user-agent'],
    //         ipAddress: ip,
    //     });
    //     if (result) return result;
    //     else {
    //         throw new HttpException(
    //             {
    //                 status: HttpStatus.UNAUTHORIZED,
    //                 error: 'Error with google login',
    //             },
    //             HttpStatus.UNAUTHORIZED,
    //         );
    //     }
    // }

    @Public()
    @UseGuards(AuthGuard('google'))
    @Get('google')
    async googleAuth(@Req() req) {
        return this.authService.googleLogin(req);
    }

    @Get('redirect')
    @UseGuards(AuthGuard('google'))
    googleAuthRedirect(@Req() req) {
        return this.authService.googleLogin(req);
    }

    @Public()
    @UseGuards(RtGuard)
    @Post('refresh')
    @HttpCode(HttpStatus.OK)
    public refreshTokens(
        @GetCurrentUser('refreshToken') refreshToken: string,
        @GetCurrentUserId() userId: number,
    ): Promise<Tokens> {
        return this.authService.refreshTokens(userId, refreshToken);
    }
}