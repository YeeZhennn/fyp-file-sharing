import { useEffect, useState } from 'react';
import axiosClient from '../axios-client.js';
import { useStateContext } from '../contexts/ContextProvider.jsx';
import Alert from '@mui/material/Alert';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import TextField from '@mui/material/TextField';

export default function FileEditDialog({ isOpen, onClose, fileId, editMode }) {
    const [errors, setErrors] = useState(null);
    const [fileName, setFileName] = useState('');
    const [fileDescription, setFileDescription] = useState('');
    const {setNotification} = useStateContext();

    useEffect(() => {
        if (fileId) {
            getFileEditInfo();
        }
    }, [fileId])

    const getFileEditInfo = () => {
        axiosClient.get('/file/' + fileId)
            .then(({data}) => {
                setFileName(data.file_name);
                setFileDescription(data.file_description);
            })
            .catch((err) => {
                console.error('Error fetching file info data:', err);
            })
    }

    const handleClose = () => {
        setErrors('');
        onClose();
    }

    const handleFileEdit = () => {
        let url;
        const payload = {
            file_name: fileName,
            file_description: fileDescription,
        }

        if (editMode === 'myFiles') {
            url = '/file/edit-myfiles/' + fileId;
        }
        else if (editMode === 'sharedWithMe') {
            url = '/file/edit-shared-with-me/' + fileId;
        }

        axiosClient.patch(url, payload)
            .then((response) => {
                if (response && response.status == 200) {
                    handleClose();
                    setNotification(response.data.message);
                }
            })
            .catch((err) => {
                const response = err.response;
                if (response && (response.status == 404 || response.status == 422)) {
                    if (response.data.errors) {
                        setErrors(response.data.errors);
                    }
                    else {
                        setErrors({
                            file: [response.data.message]
                        });
                    }
                    setTimeout(() => {
                        setErrors('');
                    }, 6000);
                }
            })
    }

    return (
        <Dialog open={isOpen} onClose={handleClose} fullWidth maxWidth="sm">
            <DialogTitle>
                Edit
            </DialogTitle>
            <DialogContent dividers>
                {errors && <Alert severity="error" sx={{ alignItems: 'center', }}>
                    {Object.keys(errors).map(key => (
                        <p key={key} style={{ margin: '5px' }}>{errors[key][0]}</p>
                    ))}
                </Alert>
                }
                <TextField id="file_name" label="File Name" type="text" value={fileName} onChange={(ev) => setFileName(ev.target.value)} variant="filled" margin="dense" fullWidth required />
                <TextField id="file_description" label="File Description" type="text" value={fileDescription} onChange={(ev) => setFileDescription(ev.target.value)} variant="filled" margin="dense" fullWidth required />
            </DialogContent>
            <DialogActions>
                <Button onClick={handleClose}>Cancel</Button>
                <Button onClick={handleFileEdit}>Edit</Button>
            </DialogActions>
        </Dialog>
    )
}