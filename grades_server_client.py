import socket
import argparse
import sys
import getpass
import hashlib
import csv


########################################################################
# Sever Class
########################################################################


class Server:
    HOSTNAME = "0.0.0.0"

    # Set the port for listening
    PORT = 50000

    RECV_BUFFER_SIZE = 1024
    MAX_CONNECTION_BACKLOG = 10
    MSG_ENCODING = "utf-8"

    # Create tuple
    SOCKET_ADDRESS = (HOSTNAME, PORT)

    def __init__(self, ip):
        # Added functionality for importing our database
        self.students = {}
        self.socket = None
        self.student_file = "./course_grades_2019.csv"

        self.create_student_dictionary()
        self.create_listen_socket()
        self.process_connections_forever()

    def create_listen_socket(self):
        """ Create a socket Server side to listen at port 50000
        """
        try:
            # Create IPv4 Socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Set socket layer socket options
            # Reuse the socket without waiting for timeouts

            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind the socket to socket address, IP Address and Port
            self.socket.bind(Server.SOCKET_ADDRESS)

            # Set the binded socket to listen
            self.socket.listen(Server.MAX_CONNECTION_BACKLOG)
            print("Listening for connections on port {} ..."
                  .format(Server.PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def process_connections_forever(self):
        """ Process the current connections forever with the
        current connections
        """
        try:
            while True:
                self.connection_handler(self.socket.accept())
        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.socket.close()
            sys.exit(1)

    def create_student_dictionary(self):
        """ Dictionary of student grades is created using the student ID
        """
        print("Data read from CSV file:")

        with open(self.student_file) as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')
            for row in csv_reader:
                print(row)
                if row[0] != 'ID Number':
                    self.students[row[0]] = {}
                    self.students[row[0]]['Password'] = row[1]
                    self.students[row[0]]['LName'] = row[2]
                    self.students[row[0]]['FName'] = row[3]
                    self.students[row[0]]['Midterm'] = row[4]
                    self.students[row[0]]['Lab1'] = row[5]
                    self.students[row[0]]['Lab2'] = row[6]
                    self.students[row[0]]['Lab3'] = row[7]
                    self.students[row[0]]['Lab4'] = row[8]

    def connection_handler(self, client):
        # Handle client connections
        connection, address_port = client
        print("Connection received from {}.".format(address_port))
        while True:
            try:
                # Receive bytes over the TCP connection. This will block
                # until "at least 1 byte or more" is available.
                recvd_bytes = connection.recv(Server.RECV_BUFFER_SIZE)

                # If recv returns with zero bytes, the other end of the
                # TCP connection has closed. If so, close the server end
                # of the connection and get the next client connection
                if len(recvd_bytes) == 0:
                    print("Closing client connection ... ")
                    connection.close()
                    break

                # Decode the received bytes back into string
                recvd_str = recvd_bytes.decode(Server.MSG_ENCODING)
                return_val = ""
                # Check what the input is, assuming valid input
                if recvd_str in Client.SUPPORTED_COMMANDS:
                    # Get average command
                    print("Received {} command from the client"
                          .format(recvd_str))
                    key = "Midterm"
                    if recvd_str != "GMA":
                        # Not the midterm command: must be a lab.
                        #  Get the number from the char at index 1
                        key = "Lab{}".format(recvd_str[2])

                    average = self.get_average(key)
                    return_val = str(average).encode(Server.MSG_ENCODING)

                else:
                    # Hashed ID/Pwd
                    print("Received ID/password hash {} from the client"
                          .format(recvd_str))
                    entry = self.get_grades(recvd_str)
                    return_val = entry.encode(Server.MSG_ENCODING)
                    # Send the received bytes back to the client.
                connection.sendall(return_val)

            except KeyboardInterrupt:
                print()
                print("Closing client connection ... ")
                connection.close()
                break

    def get_average(self, assess):
        """ Parses database and averages all of the grades for a given
        assessment that is inputted. Midterms or labs
        """
        total = 0
        for stud in self.students:
            total += int((self.students[stud][assess]))
        avg = float(total / (len(self.students)))
        print("Average = ", avg)
        return avg

    def get_grades(self, password):
        """ This method receives the hash encoded password to compare to.
        It then creates a hash encoding of all the passwords in the
        database and compares the created hash to the received hash
        then prints it out
        """
        for student_id in self.students:
            hashobj = hashlib.sha256()
            hashobj.update(student_id.encode(Server.MSG_ENCODING))
            hashobj.update((self.students[student_id]['Password'])
                           .encode(Server.MSG_ENCODING))
            if hashobj.hexdigest() == password:  
                # Generated hash is true to the user inputted 
                # Match: return row[2:]
                info = "Last name: {}, First name: {}, Midterm: {}, Lab1: {}, \
                        Lab2: {}, Lab3: {},Lab4: {}".format(
                            self.students[student_id]['LName'],
                            self.students[student_id]['FName'],
                            self.students[student_id]['Midterm'],
                            self.students[student_id]['Lab1'],
                            self.students[student_id]['Lab2'],
                            self.students[student_id]['Lab3'],
                            self.students[student_id]['Lab4']
                        )
                print("Correct password, Match found")
                return info
        print("No match found for password")
        return "Could not find grades for entered ID/Password combination"


########################################################################
#   Client Class
########################################################################


class Client:
    #   SERVER_HOSTNAME = socket.gethostname()
    RECV_BUFFER_SIZE = 1024

    SUPPORTED_COMMANDS = ["GG", "GMA", "GL1A", "GL2A", "GL3A", "GL4A"]

    def __init__(self, ip):
        self.SERVER_HOSTNAME = ip
        self.send_console_input_forever()
        self.send_console_input_forever()
        self.socket = None
        self.input_text = ""

    def get_socket(self):
        try:
            # Create an IPv4 TCP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connect_to_server(self):
        try:
            # Connect to the server using its socket address tuple.
            self.socket.connect((self.SERVER_HOSTNAME, Server.PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def get_console_input(self):
        # Get a command from the user. If it is supported it will break the loop and be sent to the server.
        while True:
            self.input_text = input("Input command: ")
            print("Command entered: {}".format(self.input_text))
            if self.input_text not in self.SUPPORTED_COMMANDS:
                # Invalid input argument
                print("Invalid input: Command must be one of {}"
                      .format(self.SUPPORTED_COMMANDS))
                self.input_text = ""
            elif self.input_text == "GG":
                # Get grades command: get ID/password and hash them
                user = input("Enter student ID: ")
                password = getpass.getpass()

                print("Received Username={}, Password={}\n"
                      .format(user, password))

                hashobj = hashlib.sha256()
                hashobj.update(user.encode(Server.MSG_ENCODING))
                hashobj.update(password.encode(Server.MSG_ENCODING))
                self.input_text = hashobj.hexdigest()
                print("Sending ID/Password hash {} to server.".format(self.input_text))
            else:
                # Other supported command: get an average
                if self.input_text == "GMA":
                    print("Fetching Midterm average")
                else:
                    print("Fetching Lab {} average".format(self.input_text[2]))
            if self.input_text != "":
                break

    def send_console_input_forever(self):

        # The main loop of the client
        while True:
            try:
                self.get_console_input()     # Validate input before connection
                self.get_socket()
                self.connect_to_server()
                self.connection_send()
                self.connection_receive()
                self.socket.close()
            except (KeyboardInterrupt, EOFError):
                print()
                print("Closing server connection ...")
                self.socket.close()
                sys.exit(1)

    def connection_send(self):
        try:
            # Send string objects over the connection. The string must
            # be encoded into bytes objects first.
            self.socket.sendall(self.input_text.encode(Server.MSG_ENCODING))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connection_receive(self):
        try:
            # Receive and print out text. The received bytes objects
            # must be decoded into string objects.
            recvd_bytes = self.socket.recv(Client.RECV_BUFFER_SIZE)

            # recv will block if nothing is available. If we receive
            # zero bytes, the connection has been closed from the
            # other end. In that case, close the connection on this
            # end and exit.
            if len(recvd_bytes) == 0:
                print("Closing server connection ... ")
                self.socket.close()
                sys.exit(1)

            print("Received: ", recvd_bytes.decode(Server.MSG_ENCODING))

        except Exception as msg:
            print(msg)
            sys.exit(1)


########################################################################
# Process command line arguments if this module is run directly.
########################################################################

if __name__ == '__main__':
    roles = {'client': Client, 'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles,
                        help='server or client role',
                        required=True, type=str)
    parser.add_argument('-i', '--ip', help='ip to connect to',
                        required=False, type=str)

    args = parser.parse_args()
    ip_addr = socket.gethostname()
    if args.ip:
        ip_addr = args.ip

    roles[args.role](ip_addr)
