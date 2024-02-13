## About Project

This project develops a web-based file sharing platform using Laravel and React frameworks. This web platform is built on top of the decentralized storage protocol, InterPlanetary File System (IPFS) to store the files uploaded. For encryption part, AES is used for content encryption during file uploading while Proxy Re-Encryption (PRE) scheme is applied for encryption on the AES key during file sharing. 

## Installation

Setup the local environment by ensuring the following services have been installed.

### XAMPP

XAMPP provides PHP, Apache and MySQL services which are required by this project. Apache is used as the HTTP web server when using PHP, while MySQL is used as the project database. 

- Install [XAMPP](https://www.apachefriends.org/download.html).

### IPFS

IPFS is used as the decentralized file storage protocol. 

1. Install [IPFS Kubo](https://docs.ipfs.tech/install/command-line/#install-official-binary-distributions).
2. Unzip the file to any file directory, such as `C:/Program Files`.
3. Navigate to the folder with the `cd C:/Program Files/kubo` command.
4. Test that Kubo installed correctly with the `ipfs --version` command.
5. Initialize IPFS node with the `ipfs init` command.
6. Start the IPFS daemon with the `ipfs daemon` command.

NOTE: The default gateway server port for IPFS daemon is 8080. Consider changing the `"Gateway"` port number in `/.ipfs/config` file if it is being used. 

```
"Addresses": {
    "Swarm": [
      "/ip4/0.0.0.0/tcp/4001",
      "/ip6/::/tcp/4001",
      "/ip4/0.0.0.0/udp/4001/quic",
      "/ip4/0.0.0.0/udp/4001/quic-v1",
      "/ip4/0.0.0.0/udp/4001/quic-v1/webtransport",
      "/ip6/::/udp/4001/quic",
      "/ip6/::/udp/4001/quic-v1",
      "/ip6/::/udp/4001/quic-v1/webtransport"
    ],
    "Announce": [],
    "AppendAnnounce": [],
    "NoAnnounce": [],
    "API": "/ip4/127.0.0.1/tcp/5001",
    "Gateway": "/ip4/127.0.0.1/tcp/8080"
  },
```

### Laravel and React Project Setup

To set up the environment for Laravel and React projects, 

1. Install [Composer](https://getcomposer.org/download/) and [Node.js](https://nodejs.org/en).
2. Navigate to the `/xampp/htdocs` folder.
3. Clone this project into the folder using `git clone` command.
4. Open this project folder using any code editor.
5. Copy `.env.example` into `.env`. Configure database and IPFS credentials.
6. Open a new terminal and run `composer install`.
7. Set the encryption key by executing `php artisan key:generate`.
8. Run migration `php artisan migrate --seed`.
9. Copy `react/.env.example` into `react/.env`. Adjust the `VITE_API_BASE_URL` parameter.
10. Open a new terminal and navigate to the react folder `cd react`. Run `npm install`.

### Go

Golang is used to run the Proxy Re-Encryption (PRE) process. 

1. Install [Go](https://go.dev/dl/) version 1.18.10. This specific version is required to use the PRE library package.
2. Open a new terminal and navigate to the golang folder `cd golang`. 
3. Disable the Go module system with the `go env -w GO111MODULE=off` command.
4. Run `go get -v github.com/SherLzp/goRecrypt` and `go get -v golang.org/x/crypto/sha3` to install the required libraries.

## Run Project

1. Open the XAMPP Control Panel and make sure both Apache and MySQL services can be started successfully.
2. Open this project folder using any code editor.
3. Open a new terminal and navigate to the kubo folder `cd C:/Program Files/kubo`. Start the IPFS daemon by executing `ipfs daemon`.
4. Open a new terminal and start the Laravel backend server by executing `php artisan serve`.
5. Open a new terminal and run `php artisan schedule:work` to invoke the scheduler. 
6. Open a new terminal and navigate to the react folder `cd react`. Start the vite server for React by executing `npm run dev`.
7. Open a new terminal and navigate to the golang folder `cd golang`. Run `go run main.go`.  