# PI Message Log Tools Executable

## Overview
This is a standalone executable version of the PI Message Log Tools application, packaged using PyInstaller. The executable contains all necessary dependencies and can be run on any Windows system without requiring Python to be installed.

## Features
- Find time ranges when an interface was in primary state
- Separate log messages for different interface instances

## Installation
No installation is required. Simply copy the `pi_log_tools.exe` file to any location on your system.

## Usage
1. Double-click on `pi_log_tools.exe` or run it from the command line:
   ```
   .\pi_log_tools.exe
   ```

2. The application will display a menu with the following options:
   ```
   What would you like to do?
   1. Find time ranges when an interface was primary
   2. Separate out log messages for separate interface instances
   3. Exit
   ```

3. Select an option by entering the corresponding number (1, 2, or 3).

4. If you select option 1 or 2, you will be prompted to enter the path to a log file.
   - For option 1, you will also need to enter the point source and interface ID.
   - For option 2, the application will create separate log files for each interface instance.

5. To exit the application, select option 3.

## Building the Executable
The executable was built using PyInstaller with the following command:
```
pyinstaller --onefile pi_log_tools.py
```

This creates a single executable file that includes all dependencies.

## Troubleshooting
- If the executable fails to run, try running it from the command line to see any error messages.
- Make sure you have the necessary permissions to read the log files and write to the output directory.
- If you encounter any issues with the application, please report them to the developer.