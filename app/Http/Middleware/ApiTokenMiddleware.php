<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use App\Models\ApiToken;
use App\Models\User;

class ApiTokenMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        $token = $request->bearerToken();

        if (!$token) {
            return response()->json([
                'success' => false,
                'message' => 'Access token required'
            ], 401);
        }

        $apiToken = ApiToken::where('token', $token)
                           ->where('expires_at', '>', now())
                           ->first();

        if (!$apiToken) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid or expired token'
            ], 401);
        }

        $user = $apiToken->user;
        
        if (!$user) {
            return response()->json([
                'success' => false,
                'message' => 'User not found'
            ], 401);
        }

        // Update last used timestamp
        $apiToken->update(['last_used_at' => now()]);

        // Set user in request
        $request->setUserResolver(function () use ($user) {
            return $user;
        });

        return $next($request);
    }
}
