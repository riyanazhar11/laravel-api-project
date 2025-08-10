<?php

namespace App\Console\Commands;

use App\Models\User;
use Illuminate\Console\Command;

class ListUsers extends Command
{
    protected $signature = 'user:list';
    protected $description = 'List all users in the system';

    public function handle()
    {
        $users = User::all(['id', 'name', 'email', 'email_verified_at', 'created_at']);
        
        if ($users->isEmpty()) {
            $this->info('No users found.');
            return 0;
        }
        
        $this->table(
            ['ID', 'Name', 'Email', 'Verified', 'Created At'],
            $users->map(function ($user) {
                return [
                    $user->id,
                    $user->name,
                    $user->email,
                    $user->email_verified_at ? 'Yes' : 'No',
                    $user->created_at->format('Y-m-d H:i:s'),
                ];
            })
        );
        
        return 0;
    }
}
