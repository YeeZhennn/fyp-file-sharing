import { useEffect, useState } from "react";
import axiosClient from "../axios-client.js";
import { useStateContext } from "../contexts/ContextProvider.jsx";
import Alert from "@mui/material/Alert";
import Grid from "@mui/material/Grid";
import Paper from "@mui/material/Paper";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import Typography from "@mui/material/Typography";
import Button from "@mui/material/Button";

export default function SharedWithMe() {
    const [errors, setErrors] = useState(null);
    const [files, setFiles] = useState([]);
    const [anchorEl, setAnchorEl] = useState(null);
    const { setNotification } = useStateContext();

    useEffect(() => {
        getWaitingApprove();
    }, []);

    const handleApproveRequest = (
        ev,
        fileId,
        requestedByUserId,
        requestedPermissionId
    ) => {
        setAnchorEl(ev.currentTarget);

        const payload = {
            requested_file_id: fileId,
            shared_with_user_id: requestedByUserId,
            permission_id: requestedPermissionId,
        };

        axiosClient
            .post("/get-all-share-requests/approve-request", payload)
            .then((response) => {
                if (response && response.status == 201) {
                    handleClose();
                    setNotification(response.data.message);
                }
            })
            .catch((err) => {
                const response = err.response;
                if (
                    response &&
                    (response.status == 404 || response.status == 422)
                ) {
                    setErrors(response.data.message);
                    setTimeout(() => {
                        setErrors("");
                    }, 6000);
                }
            });
    };

    const getWaitingApprove = () => {
        axiosClient
            .get("/get-all-share-requests")
            .then(({ data }) => {
                setFiles(data);
            })
            .catch((err) => {
                console.error("Error fetching file data:", err);
            });
    };

    return (
        <Grid>
            <Grid sx={{ mb: 3, display: "flex" }}>
                <Typography
                    variant="h6"
                    component="div"
                    sx={{ py: 0.5, flexGrow: 1 }}
                >
                    Request Waiting Approve
                </Typography>
            </Grid>
            {errors && (
                <Alert severity="error" sx={{ alignItems: "center" }}>
                    {errors}
                </Alert>
            )}
            <Paper elevation={4} sx={{ my: 2, height: 450 }}>
                <TableContainer sx={{ maxHeight: 450 }}>
                    <Table stickyHeader>
                        <TableHead>
                            <TableRow>
                                <TableCell sx={{ width: "25%" }}>
                                    Name
                                </TableCell>
                                <TableCell sx={{ width: "25%" }}>
                                    Description
                                </TableCell>
                                <TableCell sx={{ width: "25%" }}>
                                    Requested By
                                </TableCell>
                                <TableCell sx={{ width: "15%" }}>
                                    Requested Date
                                </TableCell>
                                <TableCell sx={{ width: "10%" }}></TableCell>
                            </TableRow>
                        </TableHead>
                        <TableBody>
                            {files.map((file) => (
                                <TableRow key={file.requested_file_id}>
                                    <TableCell>{file.file_name}</TableCell>
                                    <TableCell>
                                        {file.file_description}
                                    </TableCell>
                                    <TableCell>{file.name}</TableCell>
                                    <TableCell>{file.created_at}</TableCell>
                                    <TableCell>
                                        <Button
                                            variant="outlined"
                                            size="small"
                                            onClick={(ev) =>
                                                handleApproveRequest(
                                                    ev,
                                                    file.requested_file_id,
                                                    file.requested_by_user_id,
                                                    file.requested_permission_id
                                                )
                                            }
                                        >
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
    );
}
