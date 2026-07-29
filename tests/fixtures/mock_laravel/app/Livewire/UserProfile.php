<?php

namespace App\Livewire;

use Livewire\Component;
use Illuminate\Support\Facades\DB;

class UserProfile extends Component
{
    public $user_id;
    public $search;

    public function delete()
    {
        // Vulnerable raw query using user property
        DB::selectRaw("SELECT * FROM users WHERE name = '" . $this->search . "'");
    }

    public function render()
    {
        return view('livewire.user-profile');
    }
}
