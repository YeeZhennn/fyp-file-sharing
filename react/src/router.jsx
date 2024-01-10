import {Navigate, createBrowserRouter} from 'react-router-dom';
import Login from './views/Login.jsx';
import Register from './views/Register.jsx';
import NotFound from './views/NotFound.jsx';
import MyFiles from './views/MyFiles.jsx';
import SharedWithMe from './views/SharedWithMe.jsx';
import AllFiles from './views/AllFiles.jsx';
import ShareRequests from './views/ShareRequests.jsx';
import Profile from './views/Profile.jsx';
import DefaultLayout from './components/DefaultLayout.jsx';
import GuestLayout from './components/GuestLayout.jsx';

const router = createBrowserRouter([
    {
        path: "/fyp-file-sharing",
        element: <DefaultLayout />,
        children: [
            {
                path: '/fyp-file-sharing',
                element: <Navigate to="/fyp-file-sharing/myfiles" />
            },
            {
                path: '/fyp-file-sharing/myfiles',
                element: <MyFiles />
            },
            {
                path: '/fyp-file-sharing/sharedwithme',
                element: <SharedWithMe />
            },
            {
                path: '/fyp-file-sharing/allfiles',
                element: <AllFiles />
            },
            {
                path: '/fyp-file-sharing/sharerequests',
                element: <ShareRequests />
            },
            {
                path: '/fyp-file-sharing/profile',
                element: <Profile />
            },
        ]
    },
    {
        path: "/fyp-file-sharing",
        element: <GuestLayout />,
        children: [
            {
                path: '/fyp-file-sharing/login',
                element: <Login />
            },
            {
                path: '/fyp-file-sharing/register',
                element: <Register />
            },
        ]
    },
    {
        path: '*',
        element: <NotFound />
    },
])

export default router;