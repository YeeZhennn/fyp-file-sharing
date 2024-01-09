<?php

namespace App\Http\Requests;

use App\Rules\FileNameRule;
use Illuminate\Foundation\Http\FormRequest;

class StoreFileRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        return [
            'file' => [
                'bail',
                'required', 
                'file', 
                'mimes:doc,docx,xls,xlsx,ppt,pptx,csv,pdf,txt,jpeg,jpg,png,svg,zip,rar', 
                'max:10240', 
                new FileNameRule()
            ],
            'file_description' => 'required|string|max:200'
        ];
    }

    public function messages()
    {
        return [
            'file.file' => 'Please select a file to upload.',
            'file.mimes' => 'File type is not accepted. Accepted file extensions: doc, docx, xls, xlsx, ppt, pptx, csv, pdf, txt, jpeg, jpg, png, svg, zip, rar.',
            'file.max' => 'File size must not exceed 10 MB.',
            'file_description.required' => 'Please input the file description.',
        ];
    }
}
