<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegisterRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;

class AuthController extends Controller
{
    public function register(RegisterRequest $request)
    {
        $credentials = $request->validated();

        $goHost = env('GO_HOST');
        $goPort = env('GO_PORT');

        $url = "http://{$goHost}:{$goPort}/generateKeys";
        $goResponse = Http::get($url);

        if ($goResponse->successful()) {
            $goData = $goResponse->json();

            /** @var \App\Models\User $user */
            $user = User::create([
                'name' => $credentials['name'],
                'email' => $credentials['email'],
                'password' => bcrypt($credentials['password']),
                'department_id' => $credentials['department_id'],
                'role_id' => $credentials['role_id'],
                'public_key' => $goData['publicKey'],
                'private_key' => $goData['privateKey'],
            ]);

            $token = $user->createToken('main')->plainTextToken;

            return response()->json([
                'user' => $user,
                'token' => $token,
            ], 201);
        } else {
            return response()->json([
                'message' => 'Failed to fetch data from Golang.'
            ], 500);
        }
    }

    public function login(LoginRequest $request) 
    {
        $credentials = $request->validated();

        if (!Auth::attempt($credentials)) {
            return response()->json([
                'message' => 'Provided credentials are incorrect.',
            ], 422);
        }

        /** @var \App\Models\User $user */
        $user = Auth::user();
        $token = $user->createToken('main')->plainTextToken;

        return response()->json([
            'user' => $user,
            'token' => $token,
        ], 200);
    }

    public function logout(Request $request) 
    {
        $request->user()->currentAccessToken()->delete();
        return response()->json([], 204);
    }
}
