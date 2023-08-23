# AAC INSTALLER
# Powered by advanced installer 

## This program covers main system configurations which arent directly possible with Advanced Installer 

## Description
This project is an installer and automation tool designed to set up a server checklist. It automates various tasks such as moving SQL backups folder, checking extraction of contents, packaging inside Advanced Installer, getting silent installs, and running them inside a new function. The code is written in Go and utilizes PowerShell commands for specific tasks.

## Installation
To use this project, follow the instructions below:

1. Clone the repository or download the source code files.
2. Ensure Go is installed on your system.
3. Install any required dependencies.
4. Build the project using the Go build command.
5. Run the executable file generated.

## Features

### Move SQL Backups Folder
- Description: Moves the SQL backups folder to a specified location.
- TODO: Implement this feature.

### Check Extract Contents
- Description: Checks the extraction of contents.
- TODO: Implement this feature.

### Package Inside Advanced Installer
- Description: Packages the program inside Advanced Installer.
- TODO: Implement this feature.

### Get Silent Installs and Run Them Inside a New Function
- Description: Retrieves silent installs and runs them inside a new function.
- Function Name: `silentInstall`
- List of installs:
  - Postman
  - Erlang
  - Notepad ++
  - C/C++ Runtime
- TODO: Implement this feature.

### Main Installs
- Description: Calls the `SQLServer` function which installs Microsoft SQL and Studio.
- Function Name: `mainInstalls`
- TODO: Implement this feature.

### Refactoring
- Description: Refactors code to use fewer newlines and process starts. Adds support for multithreading with a maximum of 4 threads/daemons. Extra checks required for daemons.
- Update: Planned for version 2.0.0.

### Go Lang AAC Installer Source Code
- Description: Source code written in Go for the AAC Installer.
- TODO: Implement this feature.

## Author Information
- Author: Anthony Grace
- Company: AAC Solutions Pty Ltd
- Department: IT Technician
- Company/Version: Beta-0.0.2
- Date: 23/08/2023

## Disclaimer
The author of this code is not affiliated with, endorsed by, or associated with Microsoft or any of its subsidiaries or affiliates.
