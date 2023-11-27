<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\EditFileRequest;
use App\Http\Requests\ShareFileRequest;
use App\Http\Requests\StoreFileRequest;
use App\Http\Requests\RequestFileRequest;
use App\Http\Requests\ApproveFileRequest;
use App\Models\File;
use App\Models\SharedFile;
use App\Models\User;
use App\Models\ShareRequest;
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

    // Display files shared with user
    public function showSharedWithMe()
    {
        $userId = Auth::id();
        $sharedFiles = SharedFile::join('permissions', 'permissions.id', '=', 'shared_files.shared_permission_id')
            ->join('files', 'files.id', '=', 'shared_files.file_id')
            ->join('users', 'users.id', '=', 'files.uploaded_by_user_id')
            ->select('shared_files.*', 'files.file_name', 'files.file_description', 'users.name', 'permissions.permission_name')
            ->where('shared_files.shared_with_user_id', $userId)
            ->orderByDesc('shared_files.created_at')
            ->get();
        return response()->json($sharedFiles);
    }

    // Display all files uploaded by other users
    public function showAllFiles()
    {
        $userId = Auth::id();
        $sharedFiles = SharedFile::where('shared_with_user_id', '=', $userId)->pluck('file_id');
        $allFiles = File::where('uploaded_by_user_id', '!=', $userId)
            ->whereNotIn('files.id', $sharedFiles)
            ->join('users', 'users.id', '=', 'files.uploaded_by_user_id')
            ->orderByDesc('files.created_at')
            ->get();
        return response()->json($allFiles);
    }

    // Display all requests from other users to share the file
    public function showShareRequests()
    {
        $userId = Auth::id();
        $requestedFiles = ShareRequest::join('files', 'files.id', '=', 'share_requests.requested_file_id')
            ->join('permissions', 'permissions.id', '=', 'share_requests.requested_permission_id')
            ->join('users', 'users.id', '=', 'share_requests.requested_by_user_id')
            ->where('files.uploaded_by_user_id', $userId)
            ->orderByDesc('share_requests.created_at')
            ->get();
        return response()->json($requestedFiles);
    }

    // Upload file
    public function store(StoreFileRequest $request)
    {
        if ($request->hasFile('file')) {
            $data = $request->validated();
            $file = $request->file('file');

            $fileName = $file->getClientOriginalName();
            $fileDescription = $data['file_description'];
            $fileSize = $file->getSize();
            $fileMime = $file->getMimeType();
            $filePath = $file->getRealPath();
            $fileHash = ipfs()->addFromPath($filePath);
            $userId = Auth::id();

            File::create([
                'file_name' => $fileName,
                'file_description' => $fileDescription,
                'file_size' => $fileSize,
                'file_mime' => $fileMime,
                'ipfs_cid' => $fileHash,
                'uploaded_by_user_id' => $userId,
            ]);

            return response()->json([
                'message' => 'File uploaded successfully.'
            ], 201);
        }
    }

    // Request file owner to share the file
    public function requestToShare(RequestFileRequest $request)
    {
        $userId = Auth::id();
        $data = $request->validated();
        $requestedFileId = $data['requested_file_id'];
        $requestedPermissionId = $data['requested_permission_id'];

        ShareRequest::create([
            'requested_file_id' => $requestedFileId,
            'requested_by_user_id' => $userId,
            'requested_permission_id' => $requestedPermissionId,
        ]);

        return response()->json([
            'message' => 'Request send successfully.'
        ], 201);
    }

    // Approve request sent by other users to share the file
    public function approveRequest(ApproveFileRequest $request)
    {
        $data = $request->validated();
        $shareRequest = ShareRequest::where('requested_file_id', $data['requested_file_id'])->first();

        if (!$shareRequest) {
            return response()->json(['message' => 'Share request not found.'], 404);
        }

        $checkExist = SharedFile::where('file_id', $data['requested_file_id'])->where('shared_with_user_id', $data['requested_by_user_id'])->exists();

        if ($checkExist == true) {
            return response()->json([
                'message' => 'File shared with this user already.'
            ], 422);
        }

        SharedFile::create([
            'file_id' => $shareRequest->requested_file_id,
            'shared_with_user_id' => $shareRequest->requested_by_user_id,
            'shared_permission_id' => $shareRequest->requested_permission_id,
        ]);

        $shareRequest->delete();
        return response()->json(['message' => 'Request has been approved.'], 200);
    }

    // Deny request sent by other users to share the file
    public function denyRequest(Request $request)
    {
        $userId = Auth::id();
    }

    // Share file
    public function share(ShareFileRequest $request)
    {
        $data = $request->validated();
        $fileId = $data['file_id'];
        $sharedWithUserId = $data['shared_with_user_id'];

        $userId = Auth::id();
        $fileRecord = File::where('id', $fileId)->where('uploaded_by_user_id', $userId)->first();

        if (!$fileRecord) {
            return response()->json([
                'message' => 'File not found.'
            ], 404);
        }

        $checkExist = SharedFile::where('file_id', $fileId)->where('shared_with_user_id', $sharedWithUserId)->exists();

        if ($checkExist == true) {
            return response()->json([
                'message' => 'File shared with this user already.'
            ], 422);
        }

        SharedFile::create([
            'file_id' => $fileId,
            'shared_with_user_id' => $sharedWithUserId,
            'shared_permission_id' => $data['permission_id'],
        ]);

        return response()->json([
            'message' => 'File shared successfully.'
        ], 201);
    }

    // Update user access to file
    public function updateAccess(Request $request)
    {
        //
    }

    // Remove user access to file
    public function revokeAccess(Request $request)
    {
        //
    }

    // Download file uploaded by user
    public function downloadFromMyFiles($id)
    {
        $userId = Auth::id();
        $fileRecord = File::where('id', $id)->where('uploaded_by_user_id', $userId)->first();

        if (!$fileRecord) {
            return response()->json([
                'message' => 'File not found.'
            ], 404);
        }

        $fileName = $fileRecord->file_name;
        $fileMime = $fileRecord->file_mime;
        $hash = $fileRecord->ipfs_cid;
        $file = ipfs()->get($hash);

        return response($file)
            ->withHeaders([
                'Content-Type' => $fileMime,
                'Content-Disposition' => 'attachment; filename="' . $fileName . '"',
            ]);
    }

    // Download file shared to user
    public function downloadFromSharedWithMe($id)
    {
        $userId = Auth::id();
        $fileExist = File::join('shared_files', 'shared_files.file_id', '=', 'files.id')
            ->where('shared_files.file_id', $id)->where('shared_files.shared_with_user_id', $userId)->first();

        if (!$fileExist) {
            return response()->json([
                'message' => 'File not found.'
            ], 404);
        }

        $fileRecord = File::where('id', $id)->first();
        $fileName = $fileRecord->file_name;
        $fileMime = $fileRecord->file_mime;
        $hash = $fileRecord->ipfs_cid;
        $file = ipfs()->get($hash);

        return response($file)
            ->withHeaders([
                'Content-Type' => $fileMime,
                'Content-Disposition' => 'attachment; filename="' . $fileName . '"',
            ]);
    }

    // Edit file metadata uploaded by user
    public function editAtMyFiles(EditFileRequest $request, $id)
    {
        $userId = Auth::id();
        $fileRecord = File::where('id', $id)->where('uploaded_by_user_id', $userId)->first();

        if (!$fileRecord) {
            return response()->json([
                'message' => 'File not found.'
            ], 404);
        }

        $data = $request->validated();
        $existingFileExtension = pathinfo($fileRecord->file_name, PATHINFO_EXTENSION);
        $newFileName = $data['file_name'] . '.' . $existingFileExtension;
        $newFileDescription = $data['file_description'];

        if ($newFileName === $fileRecord->file_name && $newFileDescription === $fileRecord->file_description) {
            return response()->json([
                'message' => 'No changes made.'
            ], 200);
        }

        $checkExist = File::where('id', '!=', $id)->where('uploaded_by_user_id', $userId)->where('file_name', $newFileName)->exists();

        if ($checkExist == true) {
            return response()->json([
                'message' => 'A file with the same name already exists.'
            ], 422);
        }

        $fileRecord->update([
            'file_name' => $newFileName,
            'file_description' => $newFileDescription
        ]);

        return response()->json([
            'message' => 'File metadata edited successfully.'
        ], 200);
    }

    // Edit file metadata shared to user
    public function editAtSharedWithMe(EditFileRequest $request, $id)
    {
        $userId = Auth::id();
        $fileExist = File::join('shared_files', 'shared_files.file_id', '=', 'files.id')
            ->where('shared_files.file_id', $id)->where('shared_files.shared_with_user_id', $userId)->first();

        if (!$fileExist) {
            return response()->json([
                'message' => 'File not found.'
            ], 404);
        }

        $fileRecord = File::where('id', $id)->first();
        $data = $request->validated();
        $existingFileExtension = pathinfo($fileRecord->file_name, PATHINFO_EXTENSION);
        $newFileName = $data['file_name'] . '.' . $existingFileExtension;
        $newFileDescription = $data['file_description'];

        if ($newFileName === $fileRecord->file_name && $newFileDescription === $fileRecord->file_description) {
            return response()->json([
                'message' => 'No changes made.'
            ], 200);
        }

        $fileOwnerId = $fileRecord->uploaded_by_user_id;
        $checkExist = File::where('id', '!=', $id)->where('uploaded_by_user_id', $fileOwnerId)->where('file_name', $newFileName)->exists();

        if ($checkExist == true) {
            return response()->json([
                'message' => 'A file with the same name already exists at the owner side.'
            ], 422);
        }

        $fileRecord->update([
            'file_name' => $newFileName,
            'file_description' => $newFileDescription
        ]);

        return response()->json([
            'message' => 'File metadata edited successfully.'
        ], 200);
    }

    // Delete file
    public function destroy($id)
    {
        $userId = Auth::id();
        $file = File::where('id', $id)->where('uploaded_by_user_id', $userId)->first();

        if (!$file) {
            return response()->json([
                'message' => 'File not found.'
            ], 404);
        }

        $sharedFileRecords = SharedFile::where('file_id', $id)->delete();
        $file->delete();

        return response()->json([
            'message' => 'File deleted successfully.'
        ], 200);
    }

    public function getUsersToShareFile()
    {
        $userId = Auth::id();
        $users = User::where('id', '!=', $userId)->orderBy('email')->get();
        return response()->json($users);
    }

    public function getFileEditInfo($id)
    {
        $file = File::where('id', $id)->first();
        $fileNameWithoutExtension = pathinfo($file->file_name, PATHINFO_FILENAME);

        return response()->json([
            'file_name' => $fileNameWithoutExtension,
            'file_description' => $file->file_description
        ]);
    }
}
