/* eslint-disable @typescript-eslint/no-unused-vars */
import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import * as bcryptjs from 'bcryptjs';
import { CreateUserDto, UpdateAuthDto, LoginDto, RegisterUserDto } from './dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt.payload';
import { LoginResponse } from './interfaces/login-response';


@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) 
    private userModel: Model<User>,
    private jwtService: JwtService
  ){}

  async create(createUserDto: CreateUserDto): Promise<User> {
    try {
      
      const { password, ...userData } = createUserDto;
      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10),
        ...userData
      });

      await newUser.save();
      const { password:_, ...user } = newUser.toJSON();

      return user;

    } catch (error) {
      console.log("Error createUser =>", error.code);
      if (error.code === 11000) {
        throw new BadRequestException(`${createUserDto.email} already Exists!`)
      }

      throw new InternalServerErrorException('Error creating user');
    }
  }

  async login( loginDto: LoginDto): Promise<LoginResponse>{
    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email });

    if( !user){
      throw new UnauthorizedException('Invalid credentials - email');
    }

    if( !bcryptjs.compareSync(password, user.password)){
      throw new UnauthorizedException('Invalid credentials - password');
    }

    const { password:_, ...restUser } = user.toJSON();

    return {
      user: restUser,
      token: this.getJWT({ id: user.id }),
    }
  }


  async register( _registerDto: RegisterUserDto ): Promise<LoginResponse>{
    const user = await this.create( _registerDto );

    return {
      user: user,
      token: this.getJWT({ id: user._id })
    }
  }

  async findUserById( id: string){
  const user = await this.userModel.findById(id);
  const { password, ...userData } = user.toJSON();
  return userData;
}




  findAll(): Promise<User[]>{
    return this.userModel.find();
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJWT( payload: JwtPayload){
    const token = this.jwtService.sign(payload);
    return token;
  }
}
