<?php

namespace App\Traits\Mobile;

use App\Http\Responses\ResponseInterface;
use App\Http\Responses\Response as ResponsesResponse;
use App\Http\Requests\Mobile\Auth\LoginRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

trait AuthTrait
{
    public function loginToken(LoginRequest $request, $grantType, $scope = "")
    {
        $params = [
            'grant_type' => $grantType,
            'client_id' => $this->client->id,
            'client_secret' => $this->client->secret,
            'scope' => $scope
        ];

        $params['username'] = $request->membership_no;
        $params['password'] = $request->password;

        // for validate SoftLaunch
        if (!$this->CheckStatusSoftLaunchFollowMe($request->membership_no)) {
            return response()->json([
                'code' => ResponseInterface::CWL0001ERROR,
                'message' => ResponsesResponse::$statusTexts[ResponseInterface::CWL0001ERROR],
                'errors' => [
                    'field' => 'membership_no',
                    'message' => 'ยังไม่เปิดให้บริการ เนื่องจากท่านไม่ได้เป็นผู้ทดสอบ',
                ]
            ], 422);
        }

        // $request->request->add($params);

        $deviceId = $request->header('x-device-id');

        $proxy = $request->create('/oauth/token', 'POST', $params);

        $result = app()->handle($proxy);

        if ($result->isOk()) {
            $resMember = $this->authRepository->setOtpStatus($params['username'], $deviceId);
            $resMember?->MemRegis;

            $deviceId = $request->header('x-device-id');

            $this->authRepository->setPinStatus($params['username'], $deviceId);
        }

        // Decode the old content from the response
        $oldContent = json_decode($result->getContent(), true);

        // Merge the old content with the new JSON data
        $newContent = array_merge($oldContent, ['profile' => $resMember]);

        // Set the new JSON content in the response
        $response = response()->json($newContent);

        $result->setContent($response->getContent());

        return  $result;
    }

    public function refreshToken(Request $request, $grantType, $scope = "")
    {
        $params = [
            'grant_type' => $grantType,
            'client_id' => $this->client->id,
            'client_secret' => $this->client->secret,
            'scope' => $scope
        ];

        $params['refresh_token'] = $request->refresh_token;

        // $request->request->add($params);

        $proxy = $request->create('/oauth/token', 'POST', $params);

        $result = app()->handle($proxy);

        LogTrait::storeLog('mobile', 'token', 'refresh', $result);

        return  $result;
    }


    public function destroyToken(Request $request, $token)
    {
        // $params = [
        //     'token_id' => $token,
        // ];

        // $request->request->add($params);

        $proxy = Request::create("/oauth/tokens/{$token}", 'DELETE');

        $result = app()->handle($proxy);

        return  $result;
    }

    protected function revokeAccessAndRefreshTokens($tokenId)
    {
        $tokenRepository = app('Laravel\Passport\TokenRepository');
        $refreshTokenRepository = app('Laravel\Passport\RefreshTokenRepository');

        $tokenRepository->revokeAccessToken($tokenId);
        $refreshTokenRepository->revokeRefreshTokensByAccessTokenId($tokenId);
    }

    public static function CheckStatusSoftLaunchFollowMe($membership_no) {

        $check_mode = DB::table("www_constant")->pluck('www_followme_softlaunch')->first();

        if ($check_mode === 1) {
            $check_member_filter_used =  DB::table("sm_member_filter_used")
                ->where("membership_no", $membership_no
                )->where("followme_active", 1);

            //     ("SELECT count(1)
            // FROM sm_member_filter_used
            // WHERE membership_no = :membership_no
            // AND followme_active = 1", ['membership_no' => $membership_no]);

            if ($check_member_filter_used->count() > 0) {
               return true;
            } else {
                return false;
            }
        } else {
            return true;
        }

        return false;
    }
}
