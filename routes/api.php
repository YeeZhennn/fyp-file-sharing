<?php

use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\DepartmentController;
use App\Http\Controllers\Api\FileController;
use App\Http\Controllers\Api\PermissionController;
use App\Http\Controllers\Api\ProfileController;
use App\Http\Controllers\Api\RoleController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::middleware('auth:sanctum')->group(function() {
    Route::get('/user', function (Request $request) {
        return $request->user();
    });
    Route::get('/permissions', [PermissionController::class, 'index']);
    Route::get('/users-to-share', [FileController::class, 'getUsersToShareFile']);
    Route::get('/users-with-viewer-access/{id}', [FileController::class, 'getUsersWithViewerAccess']);
    Route::get('/users-with-editor-access/{id}', [FileController::class, 'getUsersWithEditorAccess']);
    Route::get('/myfiles', [FileController::class, 'showMyFiles']);
    Route::get('/shared-with-me', [FileController::class, 'showSharedWithMe']);
    Route::get('/allfiles', [FileController::class, 'showAllFiles']);
    Route::get('/requestedfiles', [FileController::class, 'showRequestedFiles']);
    Route::get('/share-requests', [FileController::class, 'showShareRequests']);
    Route::get('/file/{id}', [FileController::class, 'getFileEditInfo']);
    Route::post('/file/upload', [FileController::class, 'store']);
    Route::post('/file/request-to-share', [FileController::class, 'requestToShare']);
    Route::post('/file/approve-request', [FileController::class, 'approveRequest']);
    Route::post('/file/share', [FileController::class, 'share']);
    Route::post('/file/update-file-access', [FileController::class, 'updateFileAccess']);
    Route::post('/file/revoke-file-access', [FileController::class, 'revokeFileAccess']);
    Route::get('/file/download-myfiles/{id}', [FileController::class, 'downloadFromMyFiles']);
    Route::get('/file/download-shared-with-me/{id}', [FileController::class, 'downloadFromSharedWithMe']);
    Route::patch('/file/edit-myfiles/{id}', [FileController::class, 'editAtMyFiles']);
    Route::patch('/file/edit-shared-with-me/{id}', [FileController::class, 'editAtSharedWithMe']);
    Route::delete('/file/delete/{id}', [FileController::class, 'destroy']);
    Route::get('/profile', [ProfileController::class, 'showProfileInfo']);
    Route::post('/profile/update', [ProfileController::class, 'updateProfileInfo']);
    Route::post('/profile/update-password', [ProfileController::class, 'updatePassword']);
    Route::post('/logout', [AuthController::class, 'logout']);
});

Route::get('/departments', [DepartmentController::class, 'index']);
Route::get('/roles', [RoleController::class, 'index']);
Route::post('/register', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'login']);
