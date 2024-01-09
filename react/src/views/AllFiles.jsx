import { useEffect, useState } from 'react';
import axiosClient from '../axios-client.js';
import { useStateContext } from '../contexts/ContextProvider.jsx';
import Alert from '@mui/material/Alert';
import Button from '@mui/material/Button';
import Grid from '@mui/material/Grid';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Paper from '@mui/material/Paper';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Typography from '@mui/material/Typography';
import KeyboardArrowDownIcon from '@mui/icons-material/KeyboardArrowDown';

export default function AllFiles() {
    const [errors, setErrors] = useState(null);
    const [files, setFiles] = useState([]);
    const [requestedFiles, setRequestedFiles] = useState([]);
    const [permissionOptions, setPermissionOptions] = useState([]);
    const [selectedFileId, setSelectedFileId] = useState(null);
    const [anchorEl, setAnchorEl] = useState(null);
    const {setNotification} = useStateContext();

    useEffect(() => {
        getAllFiles();
        getAllRequestedFiles();
        getSharePermissions();
    }, [])

    const getAllFiles = () => {
        axiosClient.get('/allfiles')
            .then(({ data }) => {
                setFiles(data);
            })
            .catch((err) => {
                console.error('Error fetching file data:', err);
            })
    }

    const getAllRequestedFiles = () => {
        axiosClient.get('/requestedfiles')
            .then(({ data }) => {
                setRequestedFiles(data);
            })
            .catch((err) => {
                console.error('Error fetching file data:', err);
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

    const handleOpen = (ev, id) => {
        setAnchorEl(ev.currentTarget);
        setSelectedFileId(id);
    }

    const handleClose = () => {
        setAnchorEl(null);
        setSelectedFileId(null);
    }

    const handleRequest = (ev, permissionId) => {
        const fileId = selectedFileId;
        const payload = {
            requested_file_id: fileId,
            requested_permission_id: permissionId,
        }

        axiosClient.post('/file/request-to-share', payload)
            .then((response) => {
                if (response && response.status === 201) {
                    handleClose();
                    setNotification(response.data.message);
                    getAllFiles();
                    getAllRequestedFiles();
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
        <Grid>
            <Grid sx={{ mb: 2, display: 'flex', }}>
                <Typography variant="h6" component="div" sx={{ py: 0.5, flexGrow: 1, }}>
                    All Files
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
                                <TableCell sx={{ width: '35%', }}>Name</TableCell>
                                <TableCell sx={{ width: '40%', }}>Description</TableCell>
                                <TableCell sx={{ width: '15%', }}>Owner</TableCell>
                                <TableCell sx={{ width: '10%', }}></TableCell>
                            </TableRow>
                        </TableHead>
                        <TableBody>
                            {files.map((file) => (
                                <TableRow key={file.id}>
                                    <TableCell>{file.file_name}</TableCell>
                                    <TableCell>{file.file_description}</TableCell>
                                    <TableCell>{file.name}</TableCell>
                                    <TableCell>
                                        <Button onClick={(ev) => handleOpen(ev, file.id)} variant="outlined" size="small" aria-label="more" aria-controls="menu-list" aria-haspopup="true" endIcon={<KeyboardArrowDownIcon />}>
                                            Request
                                        </Button>
                                    </TableCell>
                                </TableRow>
                            ))}
                            <Menu
                                id="menu-list"
                                anchorEl={anchorEl}
                                open={Boolean(anchorEl)}
                                onClose={handleClose}
                                >
                                {permissionOptions.map((permission) => (
                                    <MenuItem key={permission.id} value={permission.id} onClick={(ev) => handleRequest(ev, permission.id)}>
                                        {permission.permission_name}
                                    </MenuItem>
                                ))}
                            </Menu>
                        </TableBody>
                    </Table>
                </TableContainer>
            </Paper>
            <Grid sx={{ mb: 2, display: 'flex', }}>
                <Typography variant="h6" component="div" sx={{ pt: 3, pb: 0.5, flexGrow: 1, }}>
                    Requested Files
                </Typography>
            </Grid>
            <Paper elevation={4} sx={{ height: 450, }}>
                <TableContainer sx={{ maxHeight: 450, }}>
                    <Table stickyHeader>
                        <TableHead>
                            <TableRow>
                                <TableCell sx={{ width: '30%', }}>Name</TableCell>
                                <TableCell sx={{ width: '30%', }}>Description</TableCell>
                                <TableCell sx={{ width: '10%', }}>Owner</TableCell>
                                <TableCell sx={{ width: '15%', }}>Requested Permission</TableCell>
                                <TableCell sx={{ width: '15%', }}>Requested Date</TableCell>
                            </TableRow>
                        </TableHead>
                        <TableBody>
                            {requestedFiles.map((file) => (
                                <TableRow key={file.id}>
                                    <TableCell>{file.file_name}</TableCell>
                                    <TableCell>{file.file_description}</TableCell>
                                    <TableCell>{file.name}</TableCell>
                                    <TableCell>{file.permission_name}</TableCell>
                                    <TableCell>{file.created_at}</TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                </TableContainer>
            </Paper>
        </Grid>
    )
}