# taller-ms

primero generar el proyecto

```bash
nest new gateway
nest new auth-ms
nest new task-ms
```

## Gateway
1. Instalar dependencias necesarias
```bash
# gateway
npm install class-validator class-transformer @nestjs/microservices joi dotenv rxjs nats
```
2. Desinstalar dependencias ( por comodidad ) 
```bash
npm remove @typescript-eslint/eslint-plugin eslint eslint-config-prettier
```

3. configuracion de nuestras variables de entorno ( Gateway )
```bash
PORT=3000
NATS_SERVERS="nats://localhost:4222"
```

```ts
// config/envs.ts
import "dotenv/config";
import * as joi from "joi";

interface EnvironmentVariables {
    PORT: number;
    NATS_SERVERS: string[];
}

const environmentSchema = joi.object({
    PORT: joi.number().required(),
    NATS_SERVERS: joi.array().items(joi.string()).required(),
}).unknown();

const { error, value } = environmentSchema.validate({
    ...process.env,
    NATS_SERVERS: process.env.NATS_SERVERS?.split(","),
});

if(error) {
    throw new Error(`Config validation error: ${error.message}`);
}

const environmentVariables: EnvironmentVariables = value;

export const environments = {
    port: environmentVariables.PORT,
    natsServers: environmentVariables.NATS_SERVERS,
}
```

```ts
// config/services.ts
export const NATS_SERVICE = 'NATS_SERVICE';
```

Crear un index.ts dentro de /config y exportar todo de services y envs.ts

4. configurar nuestro main.ts
```ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Logger, ValidationPipe } from '@nestjs/common';
import { environments } from './config';

async function bootstrap() {
  const logger = new Logger("GATEWAY");
  const app = await NestFactory.create(AppModule);
  app.setGlobalPrefix('api');
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true
    })
  );
  
  await app.listen(environments.port);
  logger.log(`Gateway running on port ${environments.port}`)
}
bootstrap();

```

5. crear un nuevo http/resource
```bash
nest g res auth --no-spec
```

Eliminar los servicios de auth

6. Crear Dtos de auth
```ts
// auth/dto/login-user.dto.ts
import { IsEmail, IsString } from "class-validator";

export class LoginUserDto {
    @IsString()
    @IsEmail()
    email: string;

    @IsString()
    password: string;
}
```

```ts
// auth/dto/register-user.dto.ts
import { IsEmail, IsString, Max, MaxLength, MinLength } from "class-validator";

export class RegisterUserDto {
    @IsString()
    name: string

    @IsString()
    @IsEmail()
    email:string;

    @IsString()
    @MinLength(8)
    @MaxLength(20)
    password:string;
}
```

7. Modificar `auth.controller` para usar los dtos y hacer funciones de authenticacion
```ts
// auth.controller.ts
import { Controller, Get, Post, Body, Patch, Param, Delete, Query, Req } from '@nestjs/common';
import { LoginUserDto } from './dto/login-user.dto';
import { RegisterUserDto } from './dto/register-user.dto';
import { AuthRequestController } from 'src/middlewares/auth/types/auth-request';

@Controller('auth')
export class AuthController {
  constructor() {}

  @Post('register')
  register(@Body() loginUserDto: RegisterUserDto) {
    return 'register....'
  }

  @Post('login')
  login(@Body() loginUserDto: LoginUserDto) {
    return "login..."
  }

  @Get('verify')
  verify(){
    return 'verify...'
  }
}

```

probar. api

8. importar los dtos a los controladores y usarlos
```ts
// auth.controller.ts
  @Post('register')
  register(@Body() registerUserDto: RegisterUserDto) {
    return {registerUserDto}
  }

  @Post('login')
  login(@Body() loginUserDto: LoginUserDto) {
    return {loginUserDto}
  }

```

probar api y asegurarse que esta el authmodule y el authController dentro del decorador module
```bash
curl -X POST http://localhost:3000/api/auth/login -H 'Content-Type: application/json' -d '{"email": "emi@correo.com", 
"password": "123123"}' | json_pp

```

9. crear middleware tipos para el middleware de authenticacion
```ts
// middlewares/auth/types/auth-request.ts
import { Request } from "express";

export type AuthRequestMiddleware = Request & {user?: { id: string, name: string, email: string}, token?: string}
export type AuthRequestController = Request & {user: { id: string, name: string, email: string}, token: string}
```

10. Crear middleware de authenticacion
```ts
import { Injectable, NestMiddleware, UnauthorizedException } from '@nestjs/common';
import { Response } from 'express';
import { AuthRequestMiddleware } from './types/auth-request';

@Injectable()
export class AuthMiddleware implements NestMiddleware {
  use(req: AuthRequestMiddleware, res: Response, next: () => void) {
    const [ type, token ] = req.headers.authorization.split(' ');

    if (type !== 'Bearer') {
      throw new UnauthorizedException('invalid-authorization-type-error: you are not authorized')
    }
    if(!token ) {
      throw new UnauthorizedException('invalid-authorization-token-error: token is missing')
    }else {
      req.user = { id: token }
      next();
    }
  }
}
```

11. configurar el middleware en el modulo de la aplicacion
```ts
// app.module.ts
import { MiddlewareConsumer, Module, NestModule, RequestMethod } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { AuthController } from './auth/auth.controller';
import { AuthMiddleware } from './middlewares/auth/auth.middleware';
@Module({
  imports: [AuthModule],
  controllers: [AuthController],
  providers: [],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
    .apply(AuthMiddleware)
    .forRoutes({path: 'auth/verify', method: RequestMethod.GET})
  }
}

```

12. Crear el trasportador de msg entre microservicios
```ts
// transports/nats.module.ts
import { Module } from "@nestjs/common";
import { ClientsModule, Transport } from "@nestjs/microservices";
import { environments, NATS_SERVICE } from "src/config";

@Module({
    imports: [
        ClientsModule.register([
            {
                name: NATS_SERVICE,
                transport: Transport.NATS,
                options: {
                    servers: environments.natsServers,
                },
            },
        ]),
    ],
    exports: [
        ClientsModule.register([
            {
                name: NATS_SERVICE,
                transport: Transport.NATS,
                options: {
                    servers: environments.natsServers,
                },
            },
        ]),
    ],
})
export class NatsModule {}

```

13. configurar el client proxy 
**Uso de `pipe` y `catchError`**: El **pipe** toma el observable y le aplica el operador `catchError`. Si ocurre algún error durante la operación de envío del mensaje, **`catchError`** captura ese error y arroja una excepción del tipo `RpcException` para que sea manejada de forma adecuada.
Este patrón es útil para manejar errores de una manera elegante, sin bloquear el flujo asíncrono de datos, permitiendo que la aplicación responda adecuadamente a fallos en las comunicaciones con microservicios

14. Injectamos el servicio de nats:
```ts
// auth.controller.ts
@Controller('auth')
export class AuthController {
  constructor(@Inject(NATS_SERVICE) private readonly client: ClientProxy) {}@Controller('auth')
export class AuthController {
  constructor(@Inject(NATS_SERVICE) private readonly client: ClientProxy) {}
```

solucionamos el error importando el modulo de nats al auth.module
```ts
// auth.module.ts
import { MiddlewareConsumer, Module, NestModule, RequestMethod } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { NatsModule } from 'src/transports/nats.module';

@Module({
  controllers: [AuthController],
  imports: [NatsModule]
})
export class AuthModule {}

```

```ts
// app.module.ts
import { MiddlewareConsumer, Module, NestModule, RequestMethod } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { AuthController } from './auth/auth.controller';
import { AuthMiddleware } from './middlewares/auth/auth.middleware';
import { NatsModule } from './transports/nats.module';
@Module({
  imports: [AuthModule, NatsModule],
  controllers: [AuthController],
  providers: [],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
    .apply(AuthMiddleware)
    .forRoutes({path: 'auth/verify', method: RequestMethod.GET})
  }
}
```

15. en la raiz de nuestro proyecto creamos un archivo .yml
```yml
# root/docker-compose.yml
services:
  nats-server: 
    image: nats:latest
    ports: 
    - "4222:4222"
```

```bash
# root
docker compose up -d
```

Actualizamos el controlador de auth
```ts
import { Controller, Get, Post, Body, Req, Inject } from '@nestjs/common';
import { ClientProxy, RpcException } from '@nestjs/microservices';
import { LoginUserDto } from './dto/login-user.dto';
import { RegisterUserDto } from './dto/register-user.dto';
import { AuthRequestController } from 'src/middlewares/auth/types/auth-request';
import { NATS_SERVICE } from 'src/config';
import { catchError } from 'rxjs';



@Controller('auth')
export class AuthController {
  constructor(@Inject(NATS_SERVICE) private readonly client: ClientProxy) {}

  @Post('register')
  register(@Body() registerUserDto: RegisterUserDto) {
    return this.client.send('auth.register.user', registerUserDto)
    .pipe(
      catchError( error => {
        throw new RpcException(error)
      })
    )
  }

  @Post('login')
  login(@Body() loginUserDto: LoginUserDto) {
    return this.client.send('auth.login.user', loginUserDto)
    .pipe(
      catchError( error => {
        throw new RpcException(error);
      })
    )
  }

  @Get('verify')
  verify(@Req() req: AuthRequestController){
    console.log({user: req.user, token: req.authorizationToken})
  }
}

```

actualizamos el authRequestController type
```ts
// auth-request.ts
import { Request } from "express";

export type AuthRequestMiddleware = Request & {user?: { id: string}}
export type AuthRequestController = Request & {user: { id: string}, authorizationToken: string}
```

16. confugurar un custtom excepption filter
```ts
// common/exceptions/rpc-exception.filter.ts
import { ArgumentsHost, Catch, ExceptionFilter } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';

@Catch(RpcException)
export class RpcCustomExceptionFilter implements ExceptionFilter {
  catch(exception: RpcException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse();

    const rpcError = exception.getError();
    if (rpcError.toString().includes(`Empty response`)) {
      return response.status(500).json({
        status: 500,
        message: rpcError
          .toString()
          .substring(0, rpcError.toString().indexOf('(') - 1),
      });
    }
    if (
      typeof rpcError === 'object' &&
      'status' in rpcError &&
      'message' in rpcError
    ) {
      const status = isNaN(+rpcError.status) ? 400 : +rpcError.status;
      return response.status(status).json(rpcError);
    }
    response.status(400).json({
      status: 400,
      message: rpcError,
    });
  }
}

```
crear un archivo de barril index.ts para eexportar en common

```ts
// Agregar como global el custom filter
  app.useGlobalFilters( new RpcCustomExceptionFilter());
  await app.listen(environments.port);
  logger.log(`Gateway running on port ${environments.port}`)  app.useGlobalFilters( new RpcCustomExceptionFilter());
  await app.listen(environments.port);
  logger.log(`Gateway running on port ${environments.port}`)
```

Ir a nuestra carpeta de auth-ms e instalar las siguientes dependencias
```bash
npm install class-transformer class-validator dotenv joi rxjs bcrypt @nestjs/jwt @nestjs/microservices

npm i -D prisma
```
 tambien eliminamos eslint 

17. Eliminamos app controller y app.service porque no nos sirven
y quitamos las importaciones donde esten utilizando estos servicios `app.module.ts
`
```ts
import { Module } from "@nestjs/common";


@Module({
  imports: [],
  controllers: [],
  providers: [],
})
export class AppModule {}

```

18. Configuramos nuestras variables de entorno de auth-ms
```ts
// config/envs.ts
import * as joi from "joi";
import "dotenv/config";

interface EnvironmentVariables {
    NATS_SERVERS: string[];
    JWT_SECRET: string;
}

const environtmentSchema = joi.object({
    NATS_SERVERS: joi.array().items(joi.string()).required(),
    JWT_SECRET: joi.string().required(),
}).unknown();

const { error, value } = environtmentSchema.validate({
    ...process.env,
    NATS_SERVERS: process.env.NATS_SERVERS.split(',')
});

if( error) {
    throw new Error(`Invalid enviroment variables ${error}`);
}
const environmentVariables: EnvironmentVariables = value

export const environments = {
    natsServers: environmentVariables.NATS_SERVERS,
    jwtSecret: environmentVariables.JWT_SECRET
}
```

exportamos todo en `config/index.ts`

```ts
// services.ts
export const NATS_SERVICE = 'NATS_SERVICE'

```

19. Configurar proyecto para ser un microservicio y reciba eventos de nats
```ts
// main.ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { Logger, ValidationPipe } from '@nestjs/common';
import { environments } from './config';

async function bootstrap() {
  const logger = new Logger('Auth-Microservice')
  const app = await NestFactory.createMicroservice<MicroserviceOptions>(AppModule, {
    transport: Transport.NATS,
    options: {
      servers: environments.natsServers
    }
  });
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true
    })
  )
  logger.log('Auth-Microservice started');
  await app.listen();
}
bootstrap();

```

20. configurar controlador en auth-ms
```
nest g res auth

non-http * option*
```

21. configurar el controlador de a cuerdo con los eventos definidos en el gateway
```ts
// auth.controller.ts - auth-ms
import { Controller } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @MessagePattern('auth.register.user')
  register() {
    return this.authService.findAll();
  }

  @MessagePattern('auth.login.user')
  login() {
    return this.authService.findOne(2);
  }

  @MessagePattern('auth.verify.user')
  verify() {
    return "...verifying"
  }

}

```

Probamos nuestron endpoint y verificamos si la comunicacion es exitosa entre gateway y microservicio

22. Crear los dtos para recibir informacion en `@Payload` auth-ms, *copiar de el gateway*, despues importarlos dentro de `auth.controller.ts` de nuestro auth-ms.
```ts
import { Controller } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { AuthService } from './auth.service';
import { LoginUserDto } from './dto/login-user.dto';
import { RegisterUserDto } from './dto/register-user.dto';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @MessagePattern('auth.register.user')
  register(@Payload() registerUserDto: RegisterUserDto) {
    return {registerUserDto}
  }

  @MessagePattern('auth.login.user')
  login(@Payload() loginUserDto: LoginUserDto) {
    return {loginUserDto};
  }

  @MessagePattern('auth.verify.user')
  verify() {
    return "...verifying"
  }

}

```

Testeamos los endpoints para ver si nos retorna la informacion de los dtos
```json
// Registro
{
   "registerUserDto" : {
      "email" : "eminataren2002@gmail.com",
      "name" : "Emiliano",
      "password" : "123123123"
   }
}

// Login
{
   "loginUserDto" : {
      "email" : "emi@correo.com",
      "password" : "123123123"
   }
}
```

23. ejecutamos el siguiente comando dentro de nuestro auth-ms para generar un schema para conectarnos a nuestra base de datos

```
npx prisma init 
```

Modificar el Schema.Prisma
```ts
// This is your Prisma schema file,
// learn more about it in the docs: https://pris.ly/d/prisma-schema

// Looking for ways to speed up your queries, or scale easily with your serverless or edge functions?
// Try Prisma Accelerate: https://pris.ly/cli/accelerate-init

generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model User {
  id String @id @default(uuid()) 
  name String 
  email String @unique
  password String
  
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}

```

ahora creemos una base de datos para el desarrollo de esta aplicaicion en docker definiciendo docker-compose.yml en auth-ms
```yml
services:
  auth-ms-db: 
    container_name: auth-ms
    image: postgres:12-alpine
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=223276
      - POSTGRES_DB=auth
    volumes:
      - ./postgres:/var/lib/postgresql/data
    ports:
      - 5432:5432
    
volumes:
  postgres:
```

antes de generar el cliente de prisma cambamos el string de coneccion de nuestra bd
```ts
NATS_SERVERS="nats://localhost:4222"
JWT_SECRET=panbimbo
DATABASE_URL="postgresql://postgres:223276@localhost:5432/auth?schema=public"

```
ejecutamos el cliente de prisma para generar nuestros schemas
```bash
npx prisma migrate dev --name init
npx prisma generate
```

Registramos un user para ver si tenemos exito o algun error en la base de datos
```ts
// auth-ms/src/auth/auth.service.ts
import { Injectable } from '@nestjs/common';
import { RegisterUserDto } from './dto/register-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';


@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit{
  async onModuleInit() {
    await this.$connect()
  }
  async register(registerUserDto: RegisterUserDto) {
      const user = await this.user.create({
        data: registerUserDto
      })
      return user
  }

  async login(loginUserDto: LoginUserDto) {
    
  }
}

```

```ts
// auth-ms/src/auth/auth.controler.ts

  @MessagePattern('auth.register.user')
  register(@Payload() registerUserDto: RegisterUserDto) {
    return this.authService.register(registerUserDto)
  }

```

respuesta
```json
{
   "createdAt" : "2024-10-18T01:18:43.540Z",
   "email" : "eminataren2002@gmail.com",
   "id" : "1b38be53-6753-44b4-bd83-22515822621f",
   "name" : "Emiliano",
   "password" : "123123123",
   "updatedAt" : "2024-10-18T01:18:43.540Z"
}
```

Manejar excepciones

```ts
// auth.service.ts
  async register(registerUserDto: RegisterUserDto) {
    const exist = await this.user.findUnique({
      where:{
        email: registerUserDto.email
      }
    })
    if(exist) {
      throw new RpcException({
        status: 400,
        message: 'User already exist'
      })
    }
      const user = await this.user.create({
        data: {
          ...registerUserDto,
          password: bcrypt.hashSync(registerUserDto.password, 10)
        }
      })
      return user
  }
```

Crear metodo para firmar el token y crear una interfaz con los datos que encriptara nuestro servicio 

```ts
// interfaces/jwt-payload.interface.ts
export interface IJwtPayload {
    id: string;
    email: string;
    name: string
}
```

Importamos la interface y creamos el metodo sign

```ts
  signJwt(payload: IJwtPayload) {
    return this.jwtService.sign(payload);
  }
```

implementamos dentro de login
```ts
  async login(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;
    try {
      const user = await this.user.findUnique({
        where: {
          email: email,
        },
      });
      if (!user) {
        throw new RpcException({
          status: 400,
          message: "User does not exist or is not registered",
        });
      }
      const passwordMatch = bcrypt.compareSync(password, user.password);
      if (!passwordMatch) {
        throw new RpcException({
          status: 401,
          message: "Password is incorrect",
        });
      }
      const { password: _, createdAt: __, updatedAt: ___, ...rest } = user;
      return {
        user: rest,
        token: this.signJwt(rest),
      };
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }
  }
}

```

Si intentamos hacer login nos saldra un error porque no hemos configurado JwtService dentro de nuestro modulo, es decir:
- el tiempo de expiracion
- el secret

```bash
Potential solutions:
- Is AuthModule a valid NestJS module?
- If JwtService is a provider, is it part of the current AuthModule?
- If JwtService is exported from a separate @Module, is that module imported within AuthModule?
  @Module({
    imports: [ /* the Module containing JwtService */ ]
  })
```

para solucionar esto vamos a nuestro auth.module.ts e implementemos jwtModule
```ts
import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { environments } from 'src/config';

@Module({
  controllers: [AuthController],
  providers: [AuthService],
  imports: [
    JwtModule.register({
      global: true,
      secret: environments.jwtSecret,
      signOptions: {expiresIn: '1h'}
    })
  ]
})
export class AuthModule {}

```

y por ultimo nuestro controlador implementamos el metodo login de nuestro serevicio de auth

```ts
  @MessagePattern('auth.login.user')
  login(@Payload() loginUserDto: LoginUserDto) {
    return this.authService.login(loginUserDto);
  }

  }
```
Si hacemos login, recibiremos una respuesta como esta: 
```json
{
   "token" : "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjYxNWQyMjA4LTBjNjgtNDNhMy1iYTI2LWExYTg3MDg1YjBmYSIsIm5hbWUiOiJFbWlsaWFubyIsImVtYWlsIjoiZW1pQGdtYWlsLmNvbSIsImlhdCI6MTcyOTIyNDkzMCwiZXhwIjoxNzI5MjI4NTMwfQ.ROAI0Dh0rQy0UGGNAwMUWgPF8tlMvsa57twhAywuWAg",
   "user" : {
      "email" : "emi@gmail.com",
      "id" : "615d2208-0c68-43a3-ba26-a1a87085b0fa",
      "name" : "Emiliano"
   }
}
```

Metodo verify

```ts
  async verify(token: string) {
    try {
      const { sub: _, iat: __, exp: ___, ...user } = this.jwtService.verify(token,{
          secret: environments.jwtSecret,
      });
      return {
        user: user,
        token: this.signJwt(user),
      };
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }
  }
```

```ts
// auth.controller.ts
  @MessagePattern('auth.verify.user')
  verify(@Payload() token: string) {
    return this.authService.verify(token)
  }

```

Ahora en nuestro gateway tenemos que implementar la logica para que este midleware se comunique con el microservicio

```ts
import { Inject, Injectable, NestMiddleware, UnauthorizedException } from '@nestjs/common';
import { Response } from 'express';
import { AuthRequestMiddleware } from './types/auth-request';
import { firstValueFrom } from 'rxjs';
import { NATS_SERVICE } from 'src/config';
import { ClientProxy } from '@nestjs/microservices';

@Injectable()
export class AuthMiddleware implements NestMiddleware {
  constructor(@Inject(NATS_SERVICE) private readonly client: ClientProxy){}
  async use(req: AuthRequestMiddleware, res: Response, next: () => void) {
    const [ type, token ] = req.headers.authorization.split(' ');

    if (type !== 'Bearer') {
      throw new UnauthorizedException('invalid-authorization-type-error: you are not authorized')
    }
    if(!token ) {
      throw new UnauthorizedException('invalid-authorization-token-error: token is missing')
    }else {
      try {
      const { user, token: newToken } = await firstValueFrom(
        this.client.send('auth.verify.user', token)
      )

      req.user = user,
      req.token = newToken
      next();
     } catch (error) {
      throw new UnauthorizedException()
     }
    }
  }
}


```

Iniciamos sesion con un usuario y obtenemos su token para usarlo en una peticion get con con authorizacion typo bearer token y optenemos el resultado deseado: 
```json
{
   "token" : "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjYxNWQyMjA4LTBjNjgtNDNhMy1iYTI2LWExYTg3MDg1YjBmYSIsIm5hbWUiOiJFbWlsaWFubyIsImVtYWlsIjoiZW1pQGdtYWlsLmNvbSIsImlhdCI6MTcyOTIyNjIwMCwiZXhwIjoxNzI5MjI5ODAwfQ.N8i-sfSvI1jI8JzAaFl6yqKyPcG9-zrxQFhbROi8w0Y",
   "user" : {
      "email" : "emi@gmail.com",
      "id" : "615d2208-0c68-43a3-ba26-a1a87085b0fa",
      "name" : "Emiliano"
   }
}
```

Empezaremos a trabajar con notes-ms eliminando las dependencias inecesarias 

```bash
npm remove @typescript-eslint/eslint-plugin eslint eslint-config-prettier
```

Empezar a hacer la configuracion del proyecto para su funcionamiento
```ts
// config/service.ts
export const NATS_SERVICE = "NATS_SERVICE"
```

```ts
// config/envs.ts
import 'dotenv/config'
import * as joi from 'joi'

interface EnvironmentVariables { 
    NATS_SERVERS: string[],
}

const environmentSchema = joi.object({
    NATS_SERVERS: joi.array().items(joi.string()).required()
}).unknown()

const { error, value } = environmentSchema.validate({
    ...process.env,
    NATS_SERVERS: process.env.NATS_SERVERS.split(',')
})

if( error ) {
    throw new Error ( `EnvironmentVariables error: ${error.message}`)
}

const environmentVariables: EnvironmentVariables = value

export const environments = {
    natsServers: environmentVariables.NATS_SERVERS
}
```

corremos nuestra aplicacion y configuramos nuestro main.ts para que esto sea un microservicio

agregamos nuestras variables de entorno
```env
NATS_SERVERS="nats://localhost:4222"
```

```ts
// main.ts - notes-ms
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { environments } from './config/envs';
import { Logger, ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const logger = new Logger("Notes Microservice")
  const app = await NestFactory.createMicroservice<MicroserviceOptions>(AppModule, {
    transport: Transport.NATS,
    options: {
      servers: environments.natsServers
    }
  });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true
    })
  )

  logger.log(`Auth-ms running on ${environments.natsServers}`)
  await app.listen();
  
}
bootstrap();

```

generamos un nuevo recurso dentro de notes-ms para manejar los eventos del gateway
```
nest g res notes
( select non-http  - microservice )
```

Creamos los dtos para crear notas 
```ts
// notes/dto/create-note.dto.ts notes-ms
import { IsString, MaxLength } from "class-validator"
export class CreateNoteDto {
    @IsString()
    @MaxLength(55)
    title: string
    @IsString()
    content: string
    @IsString()
    userId: string;
}

```

configuramos nuestro notes controller
```ts
import { Controller } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { NotesService } from './notes.service';
import { CreateNoteDto } from './dto/create-note.dto';
@Controller()
export class NotesController {
  constructor(private readonly notesService: NotesService) {}

  @MessagePattern('notes.create')
  create(@Payload() createNoteDto: CreateNoteDto) {
    return this.notesService.create(createNoteDto);
  }

  @MessagePattern('notes.find')
  findAll(@Payload() id: string) {
    return this.notesService.findAll(id);
  }
}

```

Ahora vamos a configurar nuestra base de datos en prisma para las notas

```bash
npx prisma init --datasource-provider sqlite
```

```ts

generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "sqlite"
  url      = env("DATABASE_URL")
}

model Note {
  id String @id @default(uuid())
  title String
  content String
  userId String
  available Boolean @default(true)
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt() 

  @@index([available])
}
```


```bash
npx prisma migrate dev --name init
```

Vamos a confiturar nuestro controlador dentro de nuestro client gateway antes de implementar los metodos

ejecutamos el siguiente comando dentro de nuestro client gateway
```bash
nest g res notes

REST API 
```

ahora configuramos el cliente de nats dentro de nuestro controlador y los endponits para notas

```ts
// notes-module.ts - client-gateway
import { Module } from '@nestjs/common';
import { NotesController } from './notes.controller';
import { NatsModule } from 'src/transports/nats.module';

@Module({
  controllers: [NotesController],
  imports: [NatsModule]
})
export class NotesModule {}


```

```ts
// notes.controller.ts gateway
import { Controller, Get, Post, Body, Patch, Param, Delete, Req, Inject } from '@nestjs/common';
import { CreateNoteDto } from './dto/create-note.dto';
import { AuthRequestController } from 'src/middlewares/auth/types/auth-request';
import { NATS_SERVICE } from 'src/config';
import { ClientProxy } from '@nestjs/microservices';

@Controller('notes')
export class NotesController {
  constructor(@Inject(NATS_SERVICE) private readonly client: ClientProxy) {}

  @Post()
  create(@Body() createNoteDto: CreateNoteDto, @Req() req: AuthRequestController) {
    return this.client.send("notes.create", {...createNoteDto, userId: req.user.id});
  }

  @Get()
  findAll(@Req() req: AuthRequestController) {
    return this.client.send('notes.find', req.user.id)
  }

}
```

Configuramos dto de las notas 
```ts
/// notes.dto.ts client gateway
import { IsString, MaxLength } from "class-validator"

export class CreateNoteDto {
    @IsString()
    @MaxLength(55)
    title: string
    @IsString()
    content: string
}
```
Si hacemos una peticion para crear una nota esto nos marcarra un error ya que no hemos configurado el middleware en el app.module

```ts
// app.module.ts client-gateway
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
    .apply(AuthMiddleware)
    .forRoutes(
      {path: 'auth/verify', method: RequestMethod.GET},
      {path: 'notes', method: RequestMethod.GET},
      {path: 'notes', method: RequestMethod.POST}
    )
  }
}

```

Deberiamos recibir una respuesta como esta: 
```json
{
   "content" : "esta es una nota o su contenido",
   "title" : "Mi nueva nota",
   "userId" : "615d2208-0c68-43a3-ba26-a1a87085b0fa"
}
```
de igual forma con el metodo findNotes: 
```json
{
   "id" : "615d2208-0c68-43a3-ba26-a1a87085b0fa"
}
```

Vamos a configurar nuestro clientGateway para manejar excepciones del microservicio
```ts
import {
  Body,
  Controller,
  Delete,
  Get,
  Inject,
  Param,
  Patch,
  Post,
  Req,
} from "@nestjs/common";
import { CreateNoteDto } from "./dto/create-note.dto";
import { AuthRequestController } from "src/middlewares/auth/types/auth-request";
import { NATS_SERVICE } from "src/config";
import { ClientProxy, RpcException } from "@nestjs/microservices";
import { catchError } from "rxjs";

@Controller("notes")
export class NotesController {
  constructor(@Inject(NATS_SERVICE) private readonly client: ClientProxy) {}

  @Post()
  create(
    @Body() createNoteDto: CreateNoteDto,
    @Req() req: AuthRequestController,
  ) {
    return this.client.send("notes.create", {
      ...createNoteDto,
      userId: req.user.id,
    }).pipe(
      catchError((error) => {
        throw new RpcException(error);
      }),
    );
  }

  @Get()
  findAll(@Req() req: AuthRequestController) {
    return this.client.send("notes.find", req.user.id)
      .pipe(
        catchError((error) => {
          throw new RpcException(error);
        }),
      );
  }
}

```

Ahora creemos los metodos para crear y listar notas de un usuario configurando el cliente de prisma en nuestro servicio

```ts
// notes.serevice.ts
import { Injectable, OnModuleInit } from '@nestjs/common';
import { CreateNoteDto } from './dto/create-note.dto';
import { PrismaClient } from '@prisma/client';
import { RpcException } from '@nestjs/microservices';

@Injectable()
export class NotesService extends PrismaClient implements OnModuleInit {

  async onModuleInit() {
    await this.$connect()
  }
  async create(createNoteDto: CreateNoteDto) {
    try {
      return await this.note.create({
        data: createNoteDto
      })
    } catch (error) {
      throw new RpcException(error.message)
    }
  }

  async findAll(id: string) {
    return await this.note.findMany({
      where: {
        userId: id
      }
    })
  }

}

```

listo, al crear una nota podremos tener el siguiente resultado:
```json
{
   "available" : true,
   "content" : "arroz, frijol, pan bimbo, atun, ajonjoli, papas, arandanos, jugo de naranja, algo mas que se me ocurra",
   "createdAt" : "2024-10-18T06:54:30.094Z",
   "id" : "b095f43a-afa8-48f3-9f1b-fce5d5c7adac",
   "title" : "comida de maniana",
   "updatedAt" : "2024-10-18T06:54:30.094Z",
   "userId" : "615d2208-0c68-43a3-ba26-a1a87085b0fa"
}
```

listar notas: 

```json
[
   {
      "available" : true,
      "content" : "esta es una nota o su contenido",
      "createdAt" : "2024-10-18T06:53:36.118Z",
      "id" : "43e965ef-bbb3-4f4e-a451-a132bd3d66db",
      "title" : "Mi nueva nota",
      "updatedAt" : "2024-10-18T06:53:36.118Z",
      "userId" : "615d2208-0c68-43a3-ba26-a1a87085b0fa"
   },
   {
      "available" : true,
      "content" : "arroz, frijol, pan bimbo, atun, ajonjoli, papas, arandanos, jugo de naranja, algo mas que se me ocurra",
      "createdAt" : "2024-10-18T06:54:30.094Z",
      "id" : "b095f43a-afa8-48f3-9f1b-fce5d5c7adac",
      "title" : "comida de maniana",
      "updatedAt" : "2024-10-18T06:54:30.094Z",
      "userId" : "615d2208-0c68-43a3-ba26-a1a87085b0fa"
   }
]
```
