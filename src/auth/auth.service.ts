import { Injectable, ConflictException, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateUserDto } from './dto/create-user.dto';
import * as bcrypt from 'bcrypt';
import { LoginUserDto } from './dto/login-user.dto';
@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}
  async register(dto: CreateUserDto){
    const existingUser = await this.prisma.user.findUnique({
        where: {email: dto.email},
    })
    if(existingUser) {
        throw new ConflictException('User already exists');
    }
    const hashedPassword = await bcrypt.hash(dto.password, 10);
    const user = await this.prisma.user.create({
        data: {
            email: dto.email,
            name: dto.name,
            password: hashedPassword,
            
        }
    })
    const token = await this.jwtService.signAsync({userId: user.id});
    return {
        access_token: token,
    }
  }
  async login(dto: LoginUserDto){
    const user = await this.prisma.user.findUnique({
        where: {email: dto.email}
    })
    if(!user){
        throw new UnauthorizedException('Invalid credentials');
    }
    const isPasswordValid = await bcrypt.compare(dto.password, user.password);
    if(!isPasswordValid){
        throw new UnauthorizedException('Invalid credentials');
    }
    const token = await this.jwtService.signAsync({userId: user.id});
    return{
        access_token: token,
    }
  }
}
