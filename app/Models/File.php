<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class File extends Model
{
    use HasFactory;

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function shareRequests(): HasMany
    {
        return $this->hasMany(ShareRequest::class);
    }

    public function sharedFiles(): HasMany
    {
        return $this->hasMany(SharedFile::class);
    }

    protected $fillable = [
        'file_name',
        'file_description',
        'file_size',
        'file_mime',
        'ipfs_cid',
        'encrypted_aes_key',
        'uploaded_by_user_id',
    ];

    protected $casts = [
        'created_at' => 'datetime:Y-m-d',
        'updated_at' => 'datetime:Y-m-d',
    ];
}
