import { useEffect, useRef, useState } from 'react';
import axiosClient from '../axios-client.js';
import { useStateContext } from '../contexts/ContextProvider.jsx';
import UpdateShareAccessDialog from '../components/UpdateShareAccessDialog.jsx';
import Alert from '@mui/material/Alert';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import Divider from '@mui/material/Divider';
import Grid from '@mui/material/Grid';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import MenuItem from '@mui/material/MenuItem';
import TextField from '@mui/material/TextField';
import Typography from '@mui/material/Typography';

export default function FileShareDialog({ isOpen, onClose, fileId }) {
    const permissionIdRef = useRef();
    const userIdRef = useRef();

    const [errors, setErrors] = useState(null);
    const [userOptions, setUserOptions] = useState([]);
    const [permissionOptions, setPermissionOptions] = useState([]);
    const [viewers, setViewers] = useState([]);
    const [editors, setEditors] = useState([]);
    const [selectedSharedFileId, setSelectedSharedFileId] = useState(null);
    const [updateAccessDialogOpen, setUpdateAccessDialogOpen] = useState(false);
    const {setNotification} = useStateContext();

    useEffect(() => {
        if (fileId) {
            getUsers();
            getSharePermissions();
            getViewers();
            getEditors();
        }
    }, [fileId])

    const getUsers = () => {
        axiosClient.get('/users-to-share')
            .then(({data}) => {
                setUserOptions(data);
            })
            .catch((err) => {
                console.error('Error fetching user data:', err);
            })
    }

    const getSharePermissions = () => {
        axiosClient.get('/permissions')
            .then(({data}) => {
                setPermissionOptions(data);
            })
            .catch((err) => {
                console.error('Error fetching permission data:', err);
            })
    }

    const getViewers = () => {
        axiosClient.get('/users-with-viewer-access/' + fileId)
            .then(({data}) => {
                setViewers(data);
            })
            .catch((err) => {
                console.error('Error fetching viewers data:', err);
            })
    }

    const getEditors = () => {
        axiosClient.get('/users-with-editor-access/' + fileId)
            .then(({data}) => {
                setEditors(data);
            })
            .catch((err) => {
                console.error('Error fetching editors data:', err);
            })
    }

    const handleUpdateAccessDialogOpen = (ev, id) => {
        setSelectedSharedFileId(id);
        setUpdateAccessDialogOpen(true);
    }

    const handleUpdateAccessDialogClose = () => {
        setSelectedSharedFileId(null);
        setUpdateAccessDialogOpen(false);
        handleClose();
    }

    const handleClose = () => {
        setErrors('');
        onClose();
    }

    const handleFileShare = () => {
        const payload = {
            file_id: fileId,
            shared_with_user_id: userIdRef.current.value,
            permission_id: permissionIdRef.current.value,
        }

        axiosClient.post('/file/share', payload)
            .then((response) => {
                if (response && response.status == 201) {
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
                            user: [response.data.message]
                        });
                    }
                    setTimeout(() => {
                        setErrors('');
                    }, 6000);
                }
            })
    }

    const handleRevokeFileAccess = (ev, id) => {
        const payload = {
            shared_file_id: id,
        }

        axiosClient.post('/file/revoke-file-access', payload)
            .then((response) => {
                if (response && response.status == 200) {
                    handleClose();
                    setNotification(response.data.message);
                }
            })
            .catch((err) => {
                const response = err.response;
                if (response && response.status == 422) {
                    setErrors(response.data.message);
                    setTimeout(() => {
                        setErrors('');
                    }, 6000);
                }
            })
    }

    return (
        <Dialog open={isOpen} onClose={handleClose} scroll="paper" fullWidth maxWidth="sm">
            <DialogTitle>
                Share
            </DialogTitle>
            <DialogContent dividers>
                {errors && <Alert severity="error" sx={{ alignItems: 'center', }}>
                    {Object.keys(errors).map(key => (
                        <p key={key} style={{ margin: '5px' }}>{errors[key][0]}</p>
                    ))}
                </Alert>
                }
                <Grid sx={{ mb: 2, }}>
                    <TextField id="user_id" select label="Add user" defaultValue="" inputRef={userIdRef} variant="filled" margin="dense" fullWidth required>
                        {userOptions.map((user) => (
                            <MenuItem key={user.id} value={user.id}>
                                {user.email}
                            </MenuItem>
                        ))}
                    </TextField>
                    <TextField id="permission_id" select label="Permission" defaultValue="" inputRef={permissionIdRef} variant="filled" margin="dense" fullWidth required>
                        {permissionOptions.map((permission) => (
                            <MenuItem key={permission.id} value={permission.id}>
                                {permission.permission_name}
                            </MenuItem>
                        ))}
                    </TextField>
                </Grid>
                <Typography variant="button" display="block" sx={{ mt: 1, }}>
                    Users With Access
                </Typography>
                <List>
                    <Typography variant="overline" display="block">
                        Viewer
                    </Typography>
                    <Divider />
                    {viewers.map((viewer) => (
                        <ListItem key={viewer.id} disablePadding divider>
                            <ListItemText primary={viewer.name} secondary={viewer.email} />
                            <Button color="secondary" onClick={(ev) => handleUpdateAccessDialogOpen(ev, viewer.id)}>Edit</Button>
                            <Button color="error" onClick={(ev) => handleRevokeFileAccess(ev, viewer.id)}>Remove</Button>
                        </ListItem>
                    ))}
                    <Typography variant="overline" display="block" sx={{ mt: 1, }}>
                        Editor
                    </Typography>
                    <Divider />
                    {editors.map((editor) => (
                        <ListItem key={editor.id} disablePadding divider>
                            <ListItemText primary={editor.name} secondary={editor.email} />
                            <Button color="secondary" onClick={(ev) => handleUpdateAccessDialogOpen(ev, editor.id)}>Edit</Button>
                            <Button color="error" onClick={(ev) => handleRevokeFileAccess(ev, editor.id)}>Remove</Button>
                        </ListItem>
                    ))}
                </List>
                <UpdateShareAccessDialog isOpen={updateAccessDialogOpen} onClose={handleUpdateAccessDialogClose} permissionOptions={permissionOptions} sharedFileId={selectedSharedFileId} />
            </DialogContent>
            <DialogActions>
                <Button onClick={handleClose}>Cancel</Button>
                <Button onClick={handleFileShare}>Share</Button>
            </DialogActions>
        </Dialog>
    )
}