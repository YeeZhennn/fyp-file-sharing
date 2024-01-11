import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { useStateContext } from '../contexts/ContextProvider.jsx';
import axiosClient from '../axios-client.js';
import Logo from '../images/logo.png';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Grid from '@mui/material/Grid';
import MenuItem from '@mui/material/MenuItem';
import Paper from '@mui/material/Paper';
import TextField from '@mui/material/TextField';
import Typography from '@mui/material/Typography';

export default function Register() {
    const nameRef = useRef();
    const emailRef = useRef();
    const depIdRef = useRef();
    const roleIdRef = useRef();
    const passwordRef = useRef();
    const passwordConfirmationRef = useRef();

    const [errors, setErrors] = useState(null);
    const [departmentOptions, setDepartmentOptions] = useState([]);
    const [roleOptions, setRoleOptions] = useState([]);
    const {setUser, setToken} = useStateContext();

    useEffect(() => {
        getDepartments();
        getRoles();
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

    const onSubmit = (ev) => {
        ev.preventDefault();
        
        const payload = {
            name: nameRef.current.value,
            email: emailRef.current.value,
            department_id: depIdRef.current.value,
            role_id: roleIdRef.current.value,
            password: passwordRef.current.value,
            password_confirmation: passwordConfirmationRef.current.value,
        }
        
        axiosClient.post('/register', payload)
            .then(({data}) => {
                setUser(data.user);
                setToken(data.token);
            })
            .catch((err) => {
                const response = err.response;
                if (response && response.status == 422) {
                    setErrors(response.data.errors);
                }
            })
    }

    // Define components' style
    const paperStyle = { padding: '20px 30px', width: 400, margin: '20px auto' }

    return (
        <Paper elevation={4} style={paperStyle}>
            <Grid align="center">
                <Box component="img" sx={{ m: 1, height: '20%', width: '20%', }} src={Logo} />
                <Typography variant="h5" gutterBottom>
                    Register
                </Typography>
            </Grid>
            <form onSubmit={onSubmit}>
                {errors && <Alert severity="error" sx={{ alignItems: 'center', }}>
                    {Object.keys(errors).map(key => (
                        <p key={key} style={{ margin: '5px' }}>{errors[key][0]}</p>
                    ))}
                </Alert>
                }
                <TextField id="name" label="Full Name" type="text" inputRef={nameRef} variant="filled" margin="dense" fullWidth required />
                <TextField id="email" label="Email Address" type="email" inputRef={emailRef} variant="filled" margin="dense" fullWidth required />
                <TextField id="dep_id" select label="Department" defaultValue="" inputRef={depIdRef} variant="filled" margin="dense" fullWidth required>
                    {departmentOptions.map((dep) => (
                        <MenuItem key={dep.id} value={dep.id}>
                            {dep.dep_name}
                        </MenuItem>
                    ))}
                </TextField>
                <TextField id="role_id" select label="Role" defaultValue="" inputRef={roleIdRef} variant="filled" margin="dense" fullWidth required>
                    {roleOptions.map((role) => (
                        <MenuItem key={role.id} value={role.id}>
                            {role.role_name}
                        </MenuItem>
                    ))}
                </TextField>
                <TextField id="password" label="Password" type="password" inputRef={passwordRef} helperText="Must be at least 8 characters (contains number, symbol, uppercase and lowercase letters)" variant="filled" margin="dense" fullWidth required/>
                <TextField id="password_confirmation" label="Confirm Password" type="password" inputRef={passwordConfirmationRef} variant="filled" margin="dense" fullWidth required/>
                <Button type='submit' variant='contained' size="large" sx={{ mt: 2, }} fullWidth>Register</Button>
            </form>
            <Typography variant="overline" display="block" align="right" sx={{ mt: 1, }} gutterBottom>
                Already Registered? <Link to="/login">Log in your account</Link>
            </Typography>
        </Paper>
    )
}
