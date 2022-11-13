import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const GetCurrentUser = createParamDecorator(
  (context: ExecutionContext): number => {
    console.log(context);

    const request = context.switchToHttp().getRequest();
    return request.user;
  },
);