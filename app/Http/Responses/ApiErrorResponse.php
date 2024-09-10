<?php

namespace App\Http\Responses;

use App\Http\Responses\Response as ResponsesResponse;
use Exception;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\Response;
use Throwable;

class ApiErrorResponse implements Responsable
{
    public function __construct(
        private ?string $message,
        private mixed $data = [],
        private ?Throwable $exception = new Exception(),
        private string $status_code = ResponseInterface::CWL0003ERROR,
        private int $statusCode = Response::HTTP_BAD_REQUEST,
        private array $headers = [],
        private mixed $errors = [],
    ) {
    }

    public function toResponse($request)
    {
        $response = [
            'code' => $this->status_code,
            'message' => $this->message ? $this->message :  ResponsesResponse::$statusTexts[$this->status_code],
            'data' => $this->data,
            'errors' => $this->errors
        ];

        if (!is_null($this->exception) && config('app.debug')) {
            $response['debug'] = [
                'message' => $this->exception->getMessage(),
                'file' => $this->exception->getFile(),
                'line' => $this->exception->getLine(),
                'trace' => $this->exception->getTrace()
            ];
        }

        return response()->json(
            $response,
            $this->statusCode,
            $this->headers,
        );
    }
}
