import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const GetCurrentUserId = createParamDecorator(
  (context: ExecutionContext): number => {
    const request = context.switchToHttp().getRequest();
    return request.user.sub;
  },
);