import { useEffect, useState } from 'react';
import axiosClient from '../axios-client.js';
import { useStateContext } from '../contexts/ContextProvider.jsx';
import Loading from '../components/Loading.jsx';
import Alert from '@mui/material/Alert';
import Button from '@mui/material/Button';
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Typography from '@mui/material/Typography';

export default function ShareRequests() {
    const [errors, setErrors] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [requests, setRequests] = useState([]);
    const {setNotification} = useStateContext();

    useEffect(() => {
        setIsLoading(true);
        getShareRequests();
    }, [])

    const getShareRequests = () => {
        axiosClient.get('/share-requests')
            .then(({ data }) => {
                setRequests(data);
                setIsLoading(false);
            })
            .catch((err) => {
                console.error('Error fetching request data:', err);
                setIsLoading(false);
            })
    }

    const handleApproveRequest = (ev, id) => {
        const payload = {
            share_request_id: id,
        }

        axiosClient.post('/file/approve-request', payload)
            .then((response) => {
                if (response && response.status == 201) {
                    setNotification(response.data.message);
                    getShareRequests();
                }
            })
            .catch((err) => {
                const response = err.response;
                if (response && response.status == 422) {
                    setErrors(response.data.message);
                    setTimeout(() => {
                        setErrors('');
                    }, 6000);
                    getShareRequests();
                }
            })
    }

    if (isLoading) {
        return <Loading />;
    }

    return (
        <Grid>
            <Grid sx={{ mb: 2, display: 'flex', }}>
                <Typography variant="h6" component="div" sx={{ py: 0.5, flexGrow: 1, }}>
                    Share Requests
                </Typography>
            </Grid>
            {errors && <Alert severity="error" sx={{ mb: 2, alignItems: 'center', }}>
                {errors}
            </Alert>
            }
            <Paper elevation={4} sx={{ height: 450, }}>
                <TableContainer sx={{ maxHeight: 450, }}>
                    <Table stickyHeader>
                        <TableHead>
                            <TableRow>
                                <TableCell sx={{ width: '20%', }}>Name</TableCell>
                                <TableCell sx={{ width: '25%', }}>Description</TableCell>
                                <TableCell sx={{ width: '15%', }}>Requested By</TableCell>
                                <TableCell sx={{ width: '15%', }}>Requested Permission</TableCell>
                                <TableCell sx={{ width: '15%', }}>Requested Date</TableCell>
                                <TableCell sx={{ width: '10%', }}></TableCell>
                            </TableRow>
                        </TableHead>
                        <TableBody>
                            {requests.map((request) => (
                                <TableRow key={request.id}>
                                    <TableCell>{request.file_name}</TableCell>
                                    <TableCell>{request.file_description}</TableCell>
                                    <TableCell>{request.name}</TableCell>
                                    <TableCell>{request.permission_name}</TableCell>
                                    <TableCell>{request.created_at}</TableCell>
                                    <TableCell>
                                        <Button onClick={(ev) => handleApproveRequest(ev, request.id)} variant="outlined" size="small">
                                            Approve
                                        </Button>
                                    </TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                </TableContainer>
            </Paper>
        </Grid>
    )
}