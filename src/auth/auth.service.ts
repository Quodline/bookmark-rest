import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { Prisma } from '@prisma/client';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async signup({ email, password }: AuthDto) {
    const hash = await argon.hash(password);

    try {
      const user = await this.prisma.user.create({
        data: { email, pass: hash },
      });

      delete user.pass;
      return user;
    } catch (e) {
      if (
        e instanceof Prisma.PrismaClientKnownRequestError &&
        e.code === 'P2002'
      ) {
        throw new ForbiddenException('Credentials taken');
      }
      throw e;
    }
  }

  async signin({ email, password }: AuthDto) {
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (user && (await argon.verify(user.pass, password))) {
      delete user.pass;
      return user;
    }

    throw new ForbiddenException('Credentials incorrect');
  }
}
