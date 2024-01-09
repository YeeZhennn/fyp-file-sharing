import { useEffect, useRef, useState } from 'react';
import axiosClient from '../axios-client.js';
import { useStateContext } from '../contexts/ContextProvider.jsx';
import Alert from '@mui/material/Alert';
import Button from '@mui/material/Button';
import Divider from '@mui/material/Divider';
import Grid from '@mui/material/Grid';
import MenuItem from '@mui/material/MenuItem';
import Paper from '@mui/material/Paper';
import Stack from '@mui/material/Stack';
import TextField from '@mui/material/TextField';
import Typography from '@mui/material/Typography';

export default function Profile() {
    const currentPasswordRef = useRef();
    const newPasswordRef = useRef();
    const newPasswordConfirmationRef = useRef();

    const [profileErrors, setProfileErrors] = useState(null);
    const [passwordErrors, setPasswordErrors] = useState(null);
    const [departmentOptions, setDepartmentOptions] = useState([]);
    const [roleOptions, setRoleOptions] = useState([]);
    const [name, setName] = useState('');
    const [depId, setDepId] = useState('');
    const [roleId, setRoleId] = useState('');
    const {setNotification} = useStateContext();

    useEffect(() => {
        getDepartments();
        getRoles();
        getProfileInfo();
    }, [])

    const getDepartments = () => {
        axiosClient.get('/departments')
            .then(({data}) => {
                setDepartmentOptions(data);
            })
            .catch((err) => {
                console.error('Error fetching department data:', err);
            })
    }

    const getRoles = () => {
        axiosClient.get('/roles')
            .then(({data}) => {
                setRoleOptions(data);
            })
            .catch((err) => {
                console.error('Error fetching role data:', err);
            })
    }

    const getProfileInfo = () => {
        axiosClient.get('/profile')
            .then(({data}) => {
                setName(data.name);
                setDepId(data.department_id);
                setRoleId(data.role_id);
            })
            .catch((err) => {
                console.error('Error fetching profile info data:', err);
            })
    }

    const handleUpdateProfile = () => {
        const payload = {
            name: name,
            department_id: depId,
            role_id: roleId,
        }

        axiosClient.post('/profile/update', payload)
            .then((response) => {
                if (response && response.status == 200) {
                    setNotification(response.data.message);
                }
            })
            .catch((err) => {
                const response = err.response;
                if (response && response.status == 422) {
                    if (response.data.errors) {
                        setProfileErrors(response.data.errors);
                    }
                    else {
                        setProfileErrors({
                            user: [response.data.message]
                        });
                    }
                    setTimeout(() => {
                        setProfileErrors('');
                    }, 6000);
                }
            })
    }

    const handleUpdatePassword = () => {
        const payload = {
            current_password: currentPasswordRef.current.value,
            new_password: newPasswordRef.current.value,
            new_password_confirmation: newPasswordConfirmationRef.current.value,
        }

        axiosClient.post('/profile/update-password', payload)
            .then((response) => {
                if (response && response.status == 200) {
                    setNotification(response.data.message);
                }
            })
            .catch((err) => {
                const response = err.response;
                if (response && response.status == 422) {
                    if (response.data.errors) {
                        setPasswordErrors(response.data.errors);
                    }
                    else {
                        setPasswordErrors({
                            password: [response.data.message]
                        });
                    }
                    setTimeout(() => {
                        setPasswordErrors('');
                    }, 6000);
                }
            })
    }
    
    return (
        <Grid>
            <Grid sx={{ mb: 2, display: 'flex', }}>
                <Typography variant="h6" component="div" sx={{ py: 0.5, flexGrow: 1, }}>
                    Profile
                </Typography>
            </Grid>
            {profileErrors && <Alert severity="error" sx={{ mb: 2, alignItems: 'center', }}>
                {Object.keys(profileErrors).map(key => (
                    <p key={key} style={{ margin: '5px' }}>{profileErrors[key][0]}</p>
                ))}
            </Alert>
            }
            <Grid item xs={12}>
                <Paper elevation={4} sx={{ p: 2, mb: 2, height: 315, }}>
                    <Typography variant="button" display="block" gutterBottom>
                        Update Profile
                    </Typography>
                    <Divider sx={{ mb: 2, }} />
                    <TextField id="name" label="Full Name" type="text" value={name} onChange={(ev) => setName(ev.target.value)} variant="filled" margin="dense" fullWidth required />
                    <TextField id="dep_id" select label="Department" value={depId} onChange={(ev) => setDepId(ev.target.value)} variant="filled" margin="dense" fullWidth required>
                        {departmentOptions.map((dep) => (
                            <MenuItem key={dep.id} value={dep.id}>
                                {dep.dep_name}
                            </MenuItem>
                        ))}
                    </TextField>
                    <TextField id="role_id" select label="Role" value={roleId} onChange={(ev) => setRoleId(ev.target.value)} variant="filled" margin="dense" fullWidth required>
                        {roleOptions.map((role) => (
                            <MenuItem key={role.id} value={role.id}>
                                {role.role_name}
                            </MenuItem>
                        ))}
                    </TextField>
                    <Divider sx={{ mt: 2, }}/>
                    <Stack direction="row" justifyContent="flex-end">
                        <Button onClick={handleUpdateProfile} variant="outlined" sx={{ mt: 2, }}>Save</Button>
                    </Stack>
                </Paper>
            </Grid>
            {passwordErrors && <Alert severity="error" sx={{ mb: 2, alignItems: 'center', }}>
                {Object.keys(passwordErrors).map(key => (
                    <p key={key} style={{ margin: '5px' }}>{passwordErrors[key][0]}</p>
                ))}
            </Alert>
            }
            <Grid item xs={12}>
                <Paper elevation={4} sx={{ p: 2, height: 340, }}>
                    <Typography variant="button" display="block" gutterBottom>
                        Update Password
                    </Typography>
                    <Divider sx={{ mb: 2, }} />
                    <TextField id="current_password" label="Current Password" type="password" inputRef={currentPasswordRef} variant="filled" margin="dense" fullWidth required/>
                    <TextField id="new_password" label="New Password" type="password" inputRef={newPasswordRef} helperText="Must be at least 8 characters (contains number, symbol, uppercase and lowercase letters)" variant="filled" margin="dense" fullWidth required/>
                    <TextField id="new_password_confirmation" label="Confirm Password" type="password" inputRef={newPasswordConfirmationRef} variant="filled" margin="dense" fullWidth required/>
                    <Divider sx={{ mt: 2, }}/>
                    <Stack direction="row" justifyContent="flex-end">
                        <Button onClick={handleUpdatePassword} variant="outlined" sx={{ mt: 2, }}>Save</Button>
                    </Stack>
                </Paper>
            </Grid>
        </Grid>
    )
}