# Build-An-Item-Catalog
Udacity Nanodegree: Full Stack Web Developer Nanodegree Program Project04

## Project Overview

You will develop an application that provides a list of items within a variety of categories as well as provide a user registration and authentication system. Registered users will have the ability to post, edit and delete their own items.

## Prerequisites
### Programs
- Python 2.7.12: https://www.python.org/downloads/release/python-2714/
- Vagrant: https://www.virtualbox.org/wiki/Downloads
- VirtualBox: https://www.virtualbox.org/wiki/Downloads
- VM configuration files: https://github.com/udacity/fullstack-nanodegree-vm

## Notice
### How to run the project?
1. Install Vagrant, VirtualBox programs by links provided above.
2. Download VM configuration files by links provided above.
3. By using terminal (or other cmd prompt), change the directory that VM configuration files are downloaded, and start vagrant.
4. Download /catalog zip file, and unzip it inside /vagrant directory.

For example: (WHEN VM configuration files are stored at Downloads/VM/ directory.)
   <pre><code>
   $ cd Downloads
   $ cd VM
   $ cd vagrant
   $ vagrant up
   $ vagrant ssh
   $ cd /vagrant
   $ cd /catalog
   $ python database_setup.py </code></pre>

   After this process, you'll get catalog.db file.
4. To run application.py file, type <pre><code> $ python application.py</code></pre> at the terminal.
5. After running the file, you should go to "localhost:8000" or "localhost:8000/category" through browser.
