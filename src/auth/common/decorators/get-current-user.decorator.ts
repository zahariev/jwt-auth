import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const GetCurrentUser = createParamDecorator(
  (context: ExecutionContext): number => {
    const request = context.switchToHttp().getRequest();
    return request.user;
  },
);