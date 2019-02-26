# client-server-database
The following is a basic client/server script that is written in python 3. Utilizing the following python libraries for the simple project:

- socket
- argparse
- sys
- haslib
- csv
- getpass

The included python script can be used with the included bash scripts or from the command line via:
```bash
python grades_client_server.py -r client
python grades_client_server.py -r server
```
What the client does is wait for user input and check if it is one of the following commands, "GG" (get grades), "GMA" (get midterm average), "GL1A" (get lab 1 average), "GL2A" (get lab 2 average), "GL3A" (get lab 3 average), "GL4A" (get lab 4 average). The client then asks for the student ID and password which are hashed and sent to the server over the internet.

What the server does is parse the csv file in the directory and creates a python dictionary from it. The user's ID and password are verified and the inputted command is executed and then sent back to the clients terminal. 
