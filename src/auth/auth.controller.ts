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
    Request,
    UseGuards,
} from '@nestjs/common';
import { AuthDto, GoogleUserDto } from './dto';
import { Tokens } from './types';

import { GoogleOAuthGuard, RtGuard } from 'src/common/guards';
import { GetCurrentUser, Public } from 'src/common/decorators';
import { GetCurrentUserId } from 'src/common/decorators/get-current-user-id.decorator';
// import { AuthGuard } from '@nestjs/passport';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) {}

    @Public()
    @Get('google')
    @UseGuards(GoogleOAuthGuard)
    async googleAuth(@Request() req) {
        return this.authService.googleLogin(req);
    }

    @Public()
    @Get('google-redirect')
    @UseGuards(GoogleOAuthGuard)
    googleAuthRedirect(@Request() req) {
        return this.authService.googleLogin(req);
    }

    @Public()
    @Get('google/ui-login')
    async googleLogin(
        @Body() body: GoogleUserDto,
        @Ip() ip: string, // @Req() req,
    ): Promise<Tokens> {
        // console.log('googleLogin', body);

        const result = await this.authService.loginGoogleUser(body, ip);
        if (result) {
            return result;
        } else {
            throw new HttpException(
                {
                    status: HttpStatus.UNAUTHORIZED,
                    error: 'Error while logging in with google',
                },
                HttpStatus.UNAUTHORIZED,
            );
        }
    }

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