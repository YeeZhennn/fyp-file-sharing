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
import Menu from "@mui/material/Menu";
import MenuItem from "@mui/material/MenuItem";
import KeyboardArrowDownIcon from "@mui/icons-material/KeyboardArrowDown";

export default function SharedWithMe() {
    const [errors, setErrors] = useState(null);
    const [files, setFiles] = useState([]);
    const [selectedFileId, setSelectedFileId] = useState(null);
    const [anchorEl, setAnchorEl] = useState(null);
    const { setNotification } = useStateContext();
    const [buttonText, setButtonText] = useState("Request");

    useEffect(() => {
        getAllFiles();
    }, []);

    const handleClick = (ev, id) => {
        setAnchorEl(ev.currentTarget);
        setSelectedFileId(id);
    };

    const handleClose = () => {
        setAnchorEl(null);
        setSelectedFileId(null);
    };

    const getAllFiles = () => {
        axiosClient
            .get("/get-all-files")
            .then(({ data }) => {
                setFiles(data);
            })
            .catch((err) => {
                console.error("Error fetching file data:", err);
            });
    };

    const handleRequest = (permissionId) => {
        if (!selectedFileId) {
            return;
        }

        const fileId = selectedFileId;
        const payload = {
            requested_file_id: fileId,
            requested_permission_id: permissionId,
        };

        axiosClient
            .post("/get-all-files/request-to-share", payload)
            .then((response) => {
                if (response && response.status === 201) {
                    setButtonText("Requested");
                    setNotification(response.data.message);
                    handleClose();
                }
            })
            .catch((error) => {
                console.error("Error making request:", error);
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
                    File Directory
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
                                <TableCell sx={{ width: "30%" }}>
                                    Name
                                </TableCell>
                                <TableCell sx={{ width: "35%" }}>
                                    Description
                                </TableCell>
                                <TableCell sx={{ width: "20%" }}>
                                    Owner
                                </TableCell>
                                <TableCell sx={{ width: "15%" }}></TableCell>
                            </TableRow>
                        </TableHead>
                        <TableBody>
                            {files.map((file) => (
                                <TableRow key={file.id}>
                                    <TableCell>{file.file_name}</TableCell>
                                    <TableCell>
                                        {file.file_description}
                                    </TableCell>
                                    <TableCell>{file.name}</TableCell>
                                    <TableCell>
                                        <Button
                                            variant="outlined"
                                            size="small"
                                            aria-label="more"
                                            aria-controls="menu-list"
                                            aria-haspopup="true"
                                            onClick={(ev) =>
                                                handleClick(ev, file.id)
                                            }
                                            disabled={
                                                buttonText === "Requested"
                                            }
                                            endIcon={<KeyboardArrowDownIcon />}
                                        >
                                            {buttonText}
                                        </Button>
                                    </TableCell>
                                </TableRow>
                            ))}
                            <Menu
                                id="menu-list"
                                elevation={0}
                                anchorOrigin={{
                                    vertical: "bottom",
                                    horizontal: "right",
                                }}
                                transformOrigin={{
                                    vertical: "top",
                                    horizontal: "right",
                                }}
                                MenuListProps={{
                                    "aria-labelledby": "main-button",
                                }}
                                anchorEl={anchorEl}
                                open={Boolean(anchorEl)}
                                onClose={handleClose}
                            >
                                <MenuItem onClick={() => handleRequest(2)}>
                                    Editor
                                </MenuItem>
                                <MenuItem onClick={() => handleRequest(1)}>
                                    Viewer
                                </MenuItem>
                            </Menu>
                        </TableBody>
                    </Table>
                </TableContainer>
            </Paper>
        </Grid>
    );
}
