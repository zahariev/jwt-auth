import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const GetCurrentUserId = createParamDecorator(
  (data: any, context: ExecutionContext): string => {
    const request = context.switchToHttp().getRequest();
    return request.user.sub;
  },
);