<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Responses\ApiSuccessResponse;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class AuthenticationController extends Controller
{
    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required',
            'email' => [
                'required',
            ],
            'password' => ['required'],
        ]);

        $formData = [
            'name' => $request->name,
            'email' => $request->email,
            'password' => $request->password,
        ];

        $formData['password'] = bcrypt($request->password);

        $user = User::create($formData);

        return response()->json([
            'user' => $user,
            'token' => $user->createToken('passportToken')->accessToken
        ], 200);
    }

    public function login(Request $request)
    {
        $credentials = [
            'email'    => $request->email,
            'password' => $request->password
        ];

        if (Auth::attempt($credentials)) {
            $token = Auth::user()->createToken('passportToken');

            return  new ApiSuccessResponse(
                ['access_token' => $token->accessToken, 'expires_at' => $token->token->expires_at]
            );
        }

        return response()->json([
            'error' => 'Unauthorised'
        ], 401);
    }
}
