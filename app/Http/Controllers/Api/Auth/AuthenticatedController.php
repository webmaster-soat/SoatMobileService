<?php

namespace App\Http\Controllers\Api\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Mobile\Auth\LoginRequest;
use App\Http\Responses\ApiErrorResponse;
use App\Http\Responses\ApiSuccessResponse;
use App\Http\Responses\ResponseInterface;
use App\Repositories\Mobile\AuthRepository;
use App\Services\MemberService;
use App\Traits\Mobile\AuthTrait;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\Rule;
use Laravel\Passport\Client;
use App\Traits\Mobile\LogTrait;
use App\Http\Responses\Response as ResponsesResponse;
use App\Models\Member\Member;
use App\Models\Member\ScMemConfirmDevice;
use Exception;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;
use PeterPetrus\Auth\PassportToken;
use Illuminate\Support\Str;

class AuthenticatedController extends Controller
{
    use AuthTrait;

    private $client;
    protected $authRepository;

    public function __construct(AuthRepository $authRepository)
    {
        $this->authRepository = $authRepository;

        $this->client = Client::where('password_client', 1)->first();
    }

    /**
     * Handle an incoming authentication request.
     */
    public function store(LoginRequest $request)
    {
        if (!$request->hasHeader('x-device-id')) {
            return response()->json([
                'code' => ResponseInterface::CWL0004ERROR,
                'message' => ResponsesResponse::$statusTexts[ResponseInterface::CWL0004ERROR],
                'errors' => ['field' => 'x-device-id', 'message' => 'The given header was invalid.']
            ], 422);
        }

        $request->authenticate();

        return $this->loginToken($request, 'password');
    }

    /**
     * Handle an incoming authentication refresh token request.
     */
    public function refresh(Request $request)
    {
        $request->validate([
            'refresh_token' => 'required'
        ]);

        return $this->refreshToken($request, 'refresh_token');
    }

    /**
     * Handle an incoming authentication pin login request.
     */
    public function pinLogin(Request $request)
    {
        if (!$request->hasHeader('x-device-id')) {
            return response()->json([
                'code' => ResponseInterface::CWL0004ERROR,
                'message' => ResponsesResponse::$statusTexts[ResponseInterface::CWL0004ERROR],
                'errors' => ['field' => 'x-device-id', 'message' => 'The given header was invalid.']
            ], 422);
        }

        $deviceId = $request->header('x-device-id');
        $token = new PassportToken($request->bearerToken());

        if ($token->error) {
            return new ApiErrorResponse(
                "Invalid token user id"
            );
        }

        $user = Member::find($token->user_id);
        $membership_no = $user->membership_no;

        // check deviceId
        $device = $user->getDeviceByDeviceId($deviceId);
        if ($device->count() === 0) {
            return response()->json([
                'code' => ResponseInterface::CWL0001ERROR,
                'message' => ResponsesResponse::$statusTexts[ResponseInterface::CWL0001ERROR],
                'errors' => [
                    'field' => 'mem_pincode',
                    'message' => 'เลขที่สมาชิกไม่อนุญาติบนอุปกรณ์นี้แล้ว',
                ]
            ], 401);
        }

        // for validate SoftLaunch
        if (!AuthTrait::CheckStatusSoftLaunchFollowMe($membership_no)) {
            return response()->json([
                'code' => ResponseInterface::CWL0001ERROR,
                'message' => ResponsesResponse::$statusTexts[ResponseInterface::CWL0001ERROR],
                'errors' => [
                    'field' => 'membership_no',
                    'message' => 'ยังไม่เปิดให้บริการ เนื่องจากท่านไม่ได้เป็นผู้ทดสอบ',
                ]
            ], 422);
        }

        // for validate anything
        if (RateLimiter::tooManyAttempts($this->throttleKey($membership_no, $deviceId), 3)) {
            $seconds = RateLimiter::availableIn($this->throttleKey($membership_no, $deviceId));

            throw ValidationException::withMessages([
                'mem_pincode' => trans('auth.throttle', [
                    'seconds' => $seconds % 60,
                    'minutes' => floor(($seconds % 3600) / 60),
                    'hours' => floor($seconds / 3600)
                ]),
                'limit_max' => 3,
                'limit_current' => 3,
            ]);
        }

        $validator = Validator::make($request->all(), [
            'mem_pincode' => [
                'required',
                Rule::exists('sc_confirm_device')->where('membership_no', $membership_no)->where('mem_device', $deviceId)->where('mem_status', 1),
            ],
        ]);

        if ($validator->fails()) {

            $hit = RateLimiter::hit($this->throttleKey($membership_no, $deviceId), 86400);

            return new ApiErrorResponse(
                $validator->errors()->messages()['mem_pincode'][0],
                [],
                new Exception(),
                ResponseInterface::CWL0004ERROR,
                Response::HTTP_BAD_REQUEST,
                [],
                [
                    ...$validator->errors()->messages(),
                    'limit_max' => 3,
                    'limit_current' => $hit,

                ]
            );
        }

        RateLimiter::clear($this->throttleKey($membership_no, $deviceId));

        $token = $user->createToken('PinLogin');

        $response = new ApiSuccessResponse(
            ['access_token' => $token->accessToken, 'expires_at' => $token->token->expires_at]
        );

        LogTrait::storeLog('mobile', 'login', 'pin', $response->toResponse($request));

        return $response;
    }

    /**
     * Destroy an authenticated session.
     */
    public function destroy(Request $request)
    {
        $token = $request->user()->token();

        $this->revokeAccessAndRefreshTokens($token->id);

        return response()->json([
            'message' => 'Successfully logged out'
        ]);
    }

    /**
     * Handle an incoming authentication send otp request.
     */
    public function storeSendOtp(Request $request)
    {
        $membership_no = Auth::user()->membership_no;

        $request->validate([
            'mobile_no' => [
                'required',
                'size:10',
                'exists:sm_mem_m_membership_registered,mobile_no',
                Rule::exists('sm_mem_m_membership_registered')->where('membership_no', $membership_no),
                // Rule::exists('sc_confirm_register')->where('membership_no', $membership_no)->where('otp_status', 0),
            ],
        ]);

        $memberService = new MemberService();
        $res = $memberService->send_otp($request->mobile_no, "4efe72f6aa");

        if ($res["code"] == "200SUCCESSREQOTP") {
            return new ApiSuccessResponse(
                $res['data']
            );
        }

        return new ApiErrorResponse(
            $res['message'],
            $res['data']
        );
    }

    /**
     * Handle an incoming authentication verify otp request.
     */
    public function storeVerifyOtp(Request $request)
    {
        if (!$request->hasHeader('x-device-id')) {
            return response()->json([
                'code' => ResponseInterface::CWL0004ERROR,
                'message' => ResponsesResponse::$statusTexts[ResponseInterface::CWL0004ERROR],
                'errors' => ['field' => 'x-device-id', 'message' => 'The given header was invalid.']
            ], 422);
        }

        $deviceId = $request->header('x-device-id');

        $membership_no =  Auth::user()->membership_no;

        $request->validate([
            'mobile_no' => [
                'required',
                'exists:sm_mem_m_membership_registered,mobile_no',
                Rule::exists('sm_mem_m_membership_registered')->where('membership_no', $membership_no),
            ],
            'pin' => 'required',
            'token' => 'required',
            'ref' => 'required',
        ]);

        $memberService = new MemberService();
        $res = $memberService->verify_otp($request->token, $request->pin);

        if ($res["code"] == "200VERIFYPINSUCCESS") {
            $this->authRepository->setOtpStatus($membership_no, $deviceId, 1);

            return new ApiSuccessResponse(
                $res['data']
            );
        }

        return new ApiErrorResponse(
            $res['message'],
            $res['data']
        );
    }

    /**
     * Handle an incoming authentication create pincode request.
     */
    public function storeCreatePincode(Request $request)
    {
        if (!$request->hasHeader('x-device-id')) {
            return response()->json([
                'code' => ResponseInterface::CWL0004ERROR,
                'message' => ResponsesResponse::$statusTexts[ResponseInterface::CWL0004ERROR],
                'errors' => ['field' => 'x-device-id', 'message' => 'The given header was invalid.']
            ], 422);
        }

        $deviceId = $request->header('x-device-id');
        $membership_no = Auth::user()->membership_no;

        $request->validate([
            'mem_pincode' => [
                'required',
                function ($attribute, $value, $fail) use ($membership_no, $deviceId) {
                    $scMemConfirmDevice = ScMemConfirmDevice::where('mem_device', $deviceId)->where('mem_status', '1');

                    if ($scMemConfirmDevice->count() > 0) {
                        $fail('อุปกรณ์นี้ถูกใช้งานไปแล้ว');
                    }

                    if ($scMemConfirmDevice->where('membership_no', $membership_no)->count() > 0) {
                        $fail('คุณได้สร้างรหัสผ่านไปแล้ว');
                    }
                },
            ],
        ]);

        $scMemConfirmDevice = new ScMemConfirmDevice;

        $scMemConfirmDevice->membership_no = $membership_no;
        $scMemConfirmDevice->mem_device = $deviceId;
        $scMemConfirmDevice->mem_pincode = $request->mem_pincode;
        $scMemConfirmDevice->mem_status = 1;
        $scMemConfirmDevice->operate_date = now();

        if ($scMemConfirmDevice->save()) {
            return new ApiSuccessResponse(
                ['message' => 'create pincode Successfully']
            );
        }

        return new ApiErrorResponse(
            "Error Create Pincode"
        );
    }

    /**
     * Handle an incoming authentication update pincode request.
     */
    public function storeUpdatePincode(Request $request)
    {
        if (!$request->hasHeader('x-device-id')) {
            return response()->json([
                'code' => ResponseInterface::CWL0004ERROR,
                'message' => ResponsesResponse::$statusTexts[ResponseInterface::CWL0004ERROR],
                'errors' => ['field' => 'x-device-id', 'message' => 'The given header was invalid.']
            ], 422);
        }

        $deviceId = $request->header('x-device-id');
        $membership_no = Auth::user()->membership_no;

        $request->validate([
            'mem_pincode' => [
                'required',
                'exists:sc_confirm_device,mem_pincode',
                Rule::exists('sc_confirm_device')->where('membership_no', $membership_no)->where('mem_device', $deviceId)->where('mem_status', 1),
            ],
            'mem_pincode_confirm' => [
                'required',
            ],
        ]);

        $scMemConfirmDevice = ScMemConfirmDevice::where([
            'membership_no' => $membership_no,
            'mem_device' => $deviceId,
            'mem_status' => 1,
        ]);

        $updated = $scMemConfirmDevice->update([
            'mem_pincode' => $request->mem_pincode_confirm,
            'operate_date' => now()
        ]);

        if ($updated) {
            return new ApiSuccessResponse(
                ['message' => 'update pincode Successfully']
            );
        }

        return new ApiErrorResponse(
            "Error Create Pincode"
        );
    }

    /**
     * Get the rate limiting throttle key for the request.
     */
    private function throttleKey($membership_no, $deviceId): string
    {
        return Str::transliterate(Str::lower('pin-login:' . $membership_no . '|' . $deviceId));
    }
}
