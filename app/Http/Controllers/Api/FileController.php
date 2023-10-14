<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\StoreFileRequest;
use App\Models\File;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class FileController extends Controller
{
    // Display files uploaded by user
    public function showMyFiles()
    {
        $userId = Auth::id();
        $files = File::where('uploaded_by_user_id', $userId)->orderByDesc('updated_at')->get();
        return response()->json($files);
    }

    // Display files shared to user
    public function showSharedWithMe()
    {
        //
    }

    // Upload file
    public function store(StoreFileRequest $request)
    {
        if ($request->hasFile('file')) {
            $file = $request->file('file');
            $fileName = $file->getClientOriginalName();
            $fileSize = $file->getSize();
            $filePath = $file->getRealPath();
            $fileHash = ipfs()->addFromPath($filePath);
            $userId = Auth::id();

            File::create([
                'file_name' => $fileName,
                'file_size' => $fileSize,
                'ipfs_cid' => $fileHash,
                'uploaded_by_user_id' => $userId,
            ]);

            return response()->json([
                'message' => 'File uploaded successfully'
            ], 201);
        }
    }

    // Share file
    public function share(Request $request)
    {
        //
    }

    // Remove user access to file
    public function removeAccess(Request $request)
    {
        //
    }

    // Download file uploaded by user
    public function downloadFromMyFiles(Request $request)
    {
        //
    }

    // Download file shared to user
    public function downloadFromSharedWithMe(Request $request)
    {
        //
    }

    // Rename file uploaded by user
    public function renameAtMyFiles(Request $request)
    {
        //
    }

    // Rename file shared to user
    public function renameAtSharedWithMe(Request $request)
    {
        //
    }

    // Delete file
    public function destroy(File $file)
    {
        //
    }
}