<?php

namespace App\Console\Commands;

use App\Models\User;
use Illuminate\Console\Command;

class VerifyUserEmail extends Command
{
    protected $signature = 'user:verify-email {email}';
    protected $description = 'Manually verify a user\'s email address for testing purposes';

    public function handle()
    {
        $email = $this->argument('email');
        
        $user = User::where('email', $email)->first();
        
        if (!$user) {
            $this->error("User with email '{$email}' not found.");
            return 1;
        }
        
        if ($user->isEmailVerified()) {
            $this->info("User '{$email}' is already verified.");
            return 0;
        }
        
        $user->update([
            'email_verified_at' => now(),
            'email_verification_token' => null,
            'email_verification_token_expires_at' => null,
        ]);
        
        $this->info("User '{$email}' has been verified successfully!");
        return 0;
    }
}
