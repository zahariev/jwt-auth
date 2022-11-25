import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class AuthDto {
    @IsNotEmpty()
    @IsString()
    email: string;

    @IsNotEmpty()
    @IsString()
    password: string;
}

export class GoogleUserDto {
    @IsNotEmpty()
    @IsString()
    idToken: string;

    @IsNotEmpty()
    @IsString()
    id: string;

    @IsNotEmpty()
    @IsEmail()
    email: string;
}