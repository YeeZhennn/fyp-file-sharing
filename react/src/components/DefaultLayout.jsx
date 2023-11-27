import { Link, Navigate, Outlet } from "react-router-dom";
import { useStateContext } from "../contexts/ContextProvider.jsx";
import { useState } from "react";
import axiosClient from "../axios-client.js";
import Logo from "../images/logo.png";
import Alert from "@mui/material/Alert";
import AppBar from "@mui/material/AppBar";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Divider from "@mui/material/Divider";
import Drawer from "@mui/material/Drawer";
import Grid from "@mui/material/Grid";
import List from "@mui/material/List";
import ListItemButton from "@mui/material/ListItemButton";
import ListItemText from "@mui/material/ListItemText";
import Snackbar from "@mui/material/Snackbar";
import Toolbar from "@mui/material/Toolbar";
import Typography from "@mui/material/Typography";

export default function DefaultLayout() {
    const [selectedIndex, setSelectedIndex] = useState(0);
    const [open, setOpen] = useState(true);
    const { token, setUser, setToken, notification } = useStateContext();

    if (!token) {
        return <Navigate to="/login" />;
    }

    const handleListItemClick = (ev, index) => {
        setSelectedIndex(index);
    };

    const handleNotificationClose = (event, reason) => {
        if (reason === "clickaway") {
            return;
        }

        setOpen(false);
    };

    const onLogOut = (ev) => {
        ev.preventDefault();
        axiosClient.post("/logout").then(() => {
            setUser({});
            setToken(null);
        });
    };

    return (
        <Grid sx={{ display: "flex" }}>
            <AppBar
                position="fixed"
                sx={{ zIndex: (theme) => theme.zIndex.drawer + 1 }}
            >
                <Toolbar>
                    <Box
                        component="img"
                        sx={{ mr: 1.5, height: "2.5%", width: "2.5%" }}
                        src={Logo}
                    />
                    <Typography
                        variant="button"
                        noWrap
                        component="div"
                        sx={{ flexGrow: 1 }}
                    >
                        Jabatan Kemajuan Islam Malaysia (JAKIM)
                    </Typography>
                    <Button
                        onClick={onLogOut}
                        variant="outlined"
                        color="inherit"
                    >
                        Logout
                    </Button>
                </Toolbar>
            </AppBar>
            <Drawer
                variant="permanent"
                sx={{
                    width: 240,
                    flexShrink: 0,
                    [`& .MuiDrawer-paper`]: {
                        width: 240,
                        boxSizing: "border-box",
                    },
                }}
            >
                <Toolbar />
                <Grid>
                    <List component="nav">
                        <ListItemButton
                            selected={selectedIndex === 0}
                            onClick={(ev) => handleListItemClick(ev, 0)}
                            component={Link}
                            to="/myfiles"
                        >
                            <ListItemText primary="My Files" sx={{ px: 1 }} />
                        </ListItemButton>
                        <ListItemButton
                            selected={selectedIndex === 1}
                            onClick={(ev) => handleListItemClick(ev, 1)}
                            component={Link}
                            to="/sharedwithme"
                        >
                            <ListItemText
                                primary="Shared With Me"
                                sx={{ px: 1 }}
                            />
                        </ListItemButton>
                        <ListItemButton
                            selected={selectedIndex === 2}
                            onClick={(ev) => handleListItemClick(ev, 2)}
                            component={Link}
                            to="/allfiles"
                        >
                            <ListItemText
                                primary="File Directory"
                                sx={{ px: 1 }}
                            />
                        </ListItemButton>
                        <ListItemButton
                            selected={selectedIndex === 3}
                            onClick={(ev) => handleListItemClick(ev, 3)}
                            component={Link}
                            to="/waitingapprove"
                        >
                            <ListItemText
                                primary="Request Waiting Approve"
                                sx={{ px: 1 }}
                            />
                        </ListItemButton>
                        <Divider />
                        <ListItemButton
                            selected={selectedIndex === 4}
                            onClick={(ev) => handleListItemClick(ev, 4)}
                            component={Link}
                            to="/profile"
                        >
                            <ListItemText primary="Profile" sx={{ px: 1 }} />
                        </ListItemButton>
                    </List>
                </Grid>
            </Drawer>
            <Grid component="main" sx={{ flexGrow: 1, p: 2 }}>
                <Toolbar />
                <Outlet />
            </Grid>
            {notification && (
                <Snackbar
                    open={open}
                    anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
                    autoHideDuration={6000}
                    onClose={handleNotificationClose}
                >
                    <Alert severity="success" onClose={handleNotificationClose}>
                        {notification}
                    </Alert>
                </Snackbar>
            )}
        </Grid>
    );
}
