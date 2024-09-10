<?php

namespace App\Http\Responses;

use App\Http\Interfaces\ResponseInterface;
use App\Http\Interfaces\Response as ResponsesResponse;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\Response;

class ApiSuccessResponse implements Responsable
{
    /**
     * @param  mixed  $data
     * @param  array  $metadata
     * @param  int  $code
     * @param  array  $headers
     */
    public function __construct(
        private mixed $data,
        private array $metadata = [],
        private string $status_code = ResponseInterface::CWL200SUCCESS,
        private int $code = Response::HTTP_OK,
        private array $headers = []
    ) {}

    /**
     * @param  $request
     * @return \Symfony\Component\HttpFoundation\Response|void
     */
    public function toResponse($request)
    {
        return response()->json(
            [
                'code' => $this->status_code,
                'message' => ResponsesResponse::$statusTexts[$this->status_code],
                'data' => $this->data,
                'metadata' => $this->metadata,
            ],
            $this->code,
            $this->headers
        );
    }
}
