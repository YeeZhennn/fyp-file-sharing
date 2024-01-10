import { useEffect, useState } from 'react';
import axiosClient from '../axios-client.js';
import { useStateContext } from '../contexts/ContextProvider.jsx';
import Loading from '../components/Loading.jsx';
import FileEditDialog from '../components/FileEditDialog.jsx';
import Alert from '@mui/material/Alert';
import Grid from '@mui/material/Grid';
import IconButton from '@mui/material/IconButton';
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
import MoreVertIcon from '@mui/icons-material/MoreVert';

export default function SharedWithMe() {
    const [errors, setErrors] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [files, setFiles] = useState([]);
    const [selectedFileId, setSelectedFileId] = useState(null);
    const [anchorEl, setAnchorEl] = useState(null);
    const [showEdit, setShowEdit] = useState(false);
    const [editDialogOpen, setEditDialogOpen] = useState(false);
    const {setNotification} = useStateContext();

    useEffect(() => {
        setIsLoading(true);
        getSharedFiles();
    }, [])

    const getSharedFiles = () => {
        axiosClient.get('/shared-with-me')
            .then(({data}) => {
                setFiles(data);
                setIsLoading(false);
            })
            .catch((err) => {
                console.error('Error fetching file data:', err);
                setIsLoading(false);
            })
    }

    const handleMoreIconOpen = (ev, id, permission) => {
        setAnchorEl(ev.currentTarget);
        setSelectedFileId(id);
        setShowEdit(permission === 'Editor');
    }

    const handleMoreIconClose = () => {
        setAnchorEl(null);
        setSelectedFileId(null);
    }

    const handleEditDialogOpen = () => {
        setEditDialogOpen(true);
    }

    const handleEditDialogClose = () => {
        handleMoreIconClose();
        setEditDialogOpen(false);
        getSharedFiles();
    }

    const handleFileDownload = () => {
        const fileId = selectedFileId;
        
        axiosClient.get('/file/download-shared-with-me/' + fileId, {
            responseType: 'blob',
        })
            .then((response) => {
                handleMoreIconClose();
                const href = window.URL.createObjectURL(response.data);
                const anchorElement = document.createElement('a');
                anchorElement.href = href;
                const contentDisposition = response.headers['content-disposition'];
                
                let fileName = "";

                if (contentDisposition) {
                    const fileNameMatch = contentDisposition.match(/filename="(.+)"/);

                    if (fileNameMatch.length === 2) {
                        fileName = fileNameMatch[1];
                    }
                }

                anchorElement.download = fileName;
                document.body.appendChild(anchorElement);
                anchorElement.click();
                document.body.removeChild(anchorElement);
                window.URL.revokeObjectURL(href);
            })
            .catch((err) => {
                const response = err.response;
                if (response && response.status == 404) {
                    setErrors(response.data.message);
                    setTimeout(() => {
                        setErrors('');
                    }, 6000);
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
                    Shared With Me
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
                                <TableCell sx={{ width: '25%', }}>Name</TableCell>
                                <TableCell sx={{ width: '35%', }}>Description</TableCell>
                                <TableCell sx={{ width: '20%', }}>Owner</TableCell>
                                <TableCell sx={{ width: '15%', }}>Shared Date</TableCell>
                                <TableCell sx={{ width: '5%', }}></TableCell>
                            </TableRow>
                        </TableHead>
                        <TableBody>
                            {files.map((file) => (
                                <TableRow key={file.file_id}>
                                    <TableCell>{file.file_name}</TableCell>
                                    <TableCell>{file.file_description}</TableCell>
                                    <TableCell>{file.name}</TableCell>
                                    <TableCell>{file.created_at}</TableCell>
                                    <TableCell>
                                        <IconButton aria-label="more" aria-controls="menu-list" aria-haspopup="true" onClick={(ev) => handleMoreIconOpen(ev, file.file_id, file.permission_name)} size="small">
                                            <MoreVertIcon fontSize="inherit" />
                                        </IconButton>
                                    </TableCell>
                                </TableRow>
                            ))}
                            <Menu 
                                id="menu-list"
                                anchorEl={anchorEl}
                                open={Boolean(anchorEl)}
                                onClose={handleMoreIconClose}
                                >
                                {showEdit && <MenuItem onClick={handleEditDialogOpen}>Edit</MenuItem>}
                                <MenuItem onClick={handleFileDownload}>Download</MenuItem>
                            </Menu>
                        </TableBody>
                    </Table>
                </TableContainer>
            </Paper>
            <FileEditDialog isOpen={editDialogOpen} onClose={handleEditDialogClose} fileId={selectedFileId} editMode="sharedWithMe" />
        </Grid>
    )
}