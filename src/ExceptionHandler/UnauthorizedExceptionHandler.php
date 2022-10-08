<?php

namespace Niexiawei\Auth\ExceptionHandler;

use Hyperf\ExceptionHandler\ExceptionHandler;
use Hyperf\HttpMessage\Stream\SwooleStream;
use Niexiawei\Auth\Exception\NoTokenPassedInException;
use Niexiawei\Auth\Exception\TokenInvalidException;
use Niexiawei\Auth\Exception\TokenUnableToRefreshException;
use Psr\Http\Message\ResponseInterface;
use Throwable;

class UnauthorizedExceptionHandler extends ExceptionHandler
{
    public function handle(Throwable $throwable, ResponseInterface $response): ResponseInterface
    {
        $data = json_encode(['code' => 401, 'msg' => $throwable->getMessage()], JSON_UNESCAPED_UNICODE);
        $this->stopPropagation();
        return $response->withStatus(200)->withBody(new SwooleStream($data));
    }

    public function isValid(Throwable $throwable): bool
    {
        return $throwable instanceof TokenInvalidException ||
            $throwable instanceof TokenUnableToRefreshException ||
            $throwable instanceof NoTokenPassedInException;
    }
}
