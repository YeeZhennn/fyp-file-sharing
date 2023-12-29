<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('shared_files', function (Blueprint $table) {
            $table->text('recrypt_capsule')->after('shared_permission_id')->notNull();
            $table->string('recrypt_pub')->after('shared_permission_id')->notNull();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('shared_files', function (Blueprint $table) {
            $table->dropColumn('recrypt_capsule');
            $table->dropColumn('recrypt_pub');
        });
    }
};
