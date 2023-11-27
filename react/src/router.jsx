import { Navigate, createBrowserRouter } from "react-router-dom";
import Login from "./views/Login.jsx";
import Register from "./views/Register.jsx";
import NotFound from "./views/NotFound.jsx";
import MyFiles from "./views/MyFiles.jsx";
import SharedWithMe from "./views/SharedWithMe.jsx";
import Profile from "./views/Profile.jsx";
import DefaultLayout from "./components/DefaultLayout.jsx";
import GuestLayout from "./components/GuestLayout.jsx";
import AllFiles from "./views/AllFiles.jsx";
import WaitingApprove from "./views/WaitingApprove.jsx";

const router = createBrowserRouter([
    {
        path: "/",
        element: <DefaultLayout />,
        children: [
            {
                path: "/",
                element: <Navigate to="/myfiles" />,
            },
            {
                path: "/myfiles",
                element: <MyFiles />,
            },
            {
                path: "/sharedwithme",
                element: <SharedWithMe />,
            },
            {
                path: "/profile",
                element: <Profile />,
            },
            {
                path: "/allfiles",
                element: <AllFiles />,
            },
            {
                path: "/waitingapprove",
                element: <WaitingApprove />,
            },
        ],
    },
    {
        path: "/",
        element: <GuestLayout />,
        children: [
            {
                path: "/login",
                element: <Login />,
            },
            {
                path: "/register",
                element: <Register />,
            },
        ],
    },
    {
        path: "*",
        element: <NotFound />,
    },
]);

export default router;
