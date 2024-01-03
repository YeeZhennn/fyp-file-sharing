<?php

namespace App\Console\Commands;

use App\Models\ShareRequest;
use Carbon\Carbon;
use Illuminate\Console\Command;

class ShareRequestExpiration extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'share-request:expiration';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Delete the request if the file owner does not approve it within three days.';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $expiredRequests = ShareRequest::where('created_at', '<=', Carbon::now()->subDays(3));
        $expiredRequests->delete();
    }
}
