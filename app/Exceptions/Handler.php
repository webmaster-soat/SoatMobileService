<?php

namespace App\Exceptions;

use App\Http\Responses\ResponseInterface;
use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Illuminate\Validation\ValidationException;
use Inertia\Inertia;
use Throwable;

class Handler extends ExceptionHandler
{
    /**
     * The list of the inputs that are never flashed to the session on validation exceptions.
     *
     * @var array<int, string>
     */
    protected $dontFlash = [
        'current_password',
        'password',
        'password_confirmation',
    ];

    /**
     * Register the exception handling callbacks for the application.
     */
    public function register(): void
    {
        $this->reportable(function (Throwable $e) {
            //
        });
    }

    /**
     * Convert a validation exception into a JSON response.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Validation\ValidationException  $exception
     * @return \Illuminate\Http\JsonResponse
     */
    protected function invalidJson($request, ValidationException $exception)
    {
        return response()->json([
            'code'    => ResponseInterface::CWL0004ERROR,
            'message' => $exception->getMessage(),
            'errors'  => $this->transformErrors($exception),
            // 'errors' => $exception->errors(),

        ], $exception->status);
    }

    // transform the error messages,
    private function transformErrors(ValidationException $exception)
    {
        $errors = [];

        foreach ($exception->errors() as $field => $message) {
            $errors[] = [
                'field' => $field,
                'message' => $message[0],
            ];
        }

        return $errors;
    }

    /**
     * Prepare exception for rendering.
     *
     * @param  \Throwable  $e
     * @return \Throwable
     */
    // public function render($request, Throwable $e)
    // {
    //     $response = parent::render($request, $e);

    //     // if (!$request->is(['api/*', 'admin/*'])) {
    //     //     if (!app()->environment(['local', 'testing']) && in_array($response->status(), [500, 503, 404, 403])) {
    //     //         return Inertia::render('Error', ['status' => $response->status()])
    //     //             ->toResponse($request)
    //     //             ->setStatusCode($response->status());
    //     //     } elseif ($response->status() === 419) {
    //     //         return back()->with([
    //     //             'message' => 'The page expired, please try again.',
    //     //         ]);
    //     //     }
    //     // }

    //     return $response;
    // }
}
