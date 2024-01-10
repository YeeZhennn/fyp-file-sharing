import { useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { useStateContext } from '../contexts/ContextProvider.jsx';
import axiosClient from '../axios-client.js';
import Logo from '../images/logo.png';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import TextField from '@mui/material/TextField';
import Typography from '@mui/material/Typography';

export default function Login() {
    const emailRef = useRef();
    const passwordRef = useRef();

    const [errors, setErrors] = useState(null);
    const {setUser, setToken} = useStateContext();

    const onSubmit = (ev) => {
        ev.preventDefault();
        
        const payload = {
            email: emailRef.current.value,
            password: passwordRef.current.value,
        }
        
        axiosClient.post('/login', payload)
            .then(({data}) => {
                setUser(data.user);
                setToken(data.token);
            })
            .catch((err) => {
                const response = err.response;
                if (response && response.status == 422) {
                    if (response.data.errors) {
                        setErrors(response.data.errors);
                    }
                    else {
                        setErrors({
                            email: [response.data.message]
                        });
                    }
                }
            })
    }

    // Define components' style
    const paperStyle = { padding: '20px 30px', width: 400, margin: '80px auto' }

    return (
        <Paper elevation={4} style={paperStyle}>
            <Grid align="center">
                <Box component="img" sx={{ m: 1, height: '20%', width: '20%', }} src={Logo} />
                <Typography variant="h5" gutterBottom>
                    Log in
                </Typography>
            </Grid>
            <form onSubmit={onSubmit}>
                {errors && <Alert severity="error" sx={{ alignItems: 'center', }}>
                    {Object.keys(errors).map(key => (
                        <p key={key} style={{ margin: '5px' }}>{errors[key][0]}</p>
                    ))}
                </Alert>
                }
                <TextField id="email" label="Email Address" type="email" inputRef={emailRef} variant="filled" margin="dense" fullWidth required />
                <TextField id="password" label="Password" type="password" inputRef={passwordRef} variant="filled" margin="dense" fullWidth required/>
                <Button type='submit' variant='contained' size="large" sx={{ mt: 2, }} fullWidth>Log in</Button>
            </form>
            <Typography variant="overline" display="block" align="right" sx={{ mt: 1, }} gutterBottom>
                Not Registered? <Link to="/fyp-file-sharing/register">Register an account</Link>
            </Typography>
        </Paper>
    )
}