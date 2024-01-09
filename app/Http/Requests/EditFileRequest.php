<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class EditFileRequest extends FormRequest
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
            'file_name' => 'required|string',
            'file_description' => 'required|string|max:200'
        ];
    }

    public function messages()
    {
        return [
            'file_name.required' => 'Please input the file name.',
            'file_description.required' => 'Please input the file description.',
        ];
    }
}
