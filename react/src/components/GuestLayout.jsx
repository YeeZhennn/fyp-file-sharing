import { Navigate, Outlet } from 'react-router-dom';
import { useStateContext } from '../contexts/ContextProvider';
import Grid from '@mui/material/Grid';

export default function GuestLayout() {
    const {token} = useStateContext();

    if (token) {
        return <Navigate to="/" />
    }

    return (
        <Grid>
            <Outlet />
        </Grid>
    )
}