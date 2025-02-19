# Accessible Kickstart Files for Rocky Linux 9

This repository provides kickstart files for creating accessible Rocky Linux 9 systems, designed with features for blind and visually impaired users.  Currently, it includes configurations for server and workstation installations.

## Available Kickstart Files

*   `rocky9.server.cfg`:  Kickstart file for a Rocky Linux 9 server installation.
*   `rocky9.workstation.cfg`: Kickstart file for a Rocky Linux 9 workstation installation.
*   `rocky.nvidia.cfg`: Configuration file that can be used to attempt to install NVIDIA drivers after the base system is installed.
*   `rocky.cuda.cfg`: Configuration file that can be used to install the CUDA toolkit after the NVIDIA driver is installed.

## Serving Kickstart Files

A simple Flask server is included to serve the kickstart and configuration files over a local network. This is useful for automating installations without needing a dedicated web server.

## Serving Kickstart Files

A simple Flask server is included to serve the kickstart and configuration files over a local network. This is useful for automating installations without needing a dedicated web server, and even provides the necessary bootloader command.

### Running the Server

1.  Navigate to the directory containing the Flask server script.
2.  Run the server: `python server.py`

The server will bind to all interfaces on port 5000 and print:

*   The machine's IP address.
*   An index of all `.cfg` files found in the same directory.
*   The complete bootloader command to use the kickstart file.

### Example Usage (Client Side)

The server output provides the command you need to add to your bootloader.  It will look something like this (but with the correct IP and filename):

inst.ks=http://<server_ip>:5000/rocky9-server.ks

You would append this to your boot parameters when starting the Rocky Linux 9 installer.  How you do this depends on your boot method (e.g., editing the GRUB boot menu, configuring PXE boot, etc.).  Consult your Rocky Linux documentation for details on modifying boot parameters.

For example, if you are booting from a USB drive and see the GRUB menu, you would likely press `e` to edit the boot command, add the `inst.ks` parameter to the end of the line starting with `linux`, and then press Ctrl+x to boot.

## Accessibility Features

These kickstart files aim to provide a more accessible experience for blind and visually impaired users by:

* Installing and configuring orca to start at the login screen
* Turns on accessibility features for all users
* Adds accessible packages that work well with orca
* Adds Mate Desktop to the server and work station installs (not great for heavy production but it gets me by)

## Contributing

Contributions are welcome!  If you have suggestions for improvements or want to add kickstart files for other systems, please open an issue or submit a pull request.

## License

This repository is public and free for anyone to use.  
MIT License

## Future Plans

*   Adding kickstart files for other operating systems as needed.
