<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use App\Models\User;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    // Registration method
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8',
        ]);
    
        if ($validator->fails()) {
            return response(['errors' => $validator->errors()], 422);
        }
    
        // Create a new user
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
        ]);
    
        return response(['message' => 'User registered successfully']);
    }

    // Login method
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

    if (Auth::attempt($credentials)) {
        $user = Auth::user();
        $token = $user->createToken('MyApp')->accessToken;

        return response(['user' => $user, 'access_token' => $token]);
    }

    return response(['error' => 'Unauthorized'], 401);
    }

    // Logout method
    public function logout(Request $request)
    {
        $request->user()->token()->revoke();
        return response(['message' => 'User logged out']);
    }

    // Getting the user information method
    public function user(Request $request)
    {
        return response(['user' => $request->user()]);
    }
}

