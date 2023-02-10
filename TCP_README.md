# TCP

Useful Article Link
https://www.khanacademy.org/computing/computers-and-internet/xcae6f4a7ff015e7d:the-internet/xcae6f4a7ff015e7d:transporting-packets/a/transmission-control-protocol--tcp

## TCP flag
TCP (Transmission Control Protocol) uses flags to control the flow of data between two devices in a network. The flags are included as part of the TCP header, which is added to each data packet that is sent over the network.

There are several different flags that are used in TCP, including:

* SYN (Synchronize): This flag is used to initiate a new TCP connection. When the SYN flag is set in a packet, it indicates that the sender is requesting to start a new connection.

* ACK (Acknowledgment): This flag is used to acknowledge the receipt of data packets. When the ACK flag is set in a packet, it indicates that the receiver has received the data and is sending an acknowledgment back to the sender.

* FIN (Finish): This flag is used to end an existing TCP connection. When the FIN flag is set in a packet, it indicates that the sender is finished sending data and wants to close the connection.

* RST (Reset): This flag is used to reset an existing TCP connection. When the RST flag is set in a packet, it indicates that there has been an error in the connection and that it needs to be reset.

* PSH (Push): This flag is used to push data to the receiving device as soon as possible, rather than waiting for the buffer to fill up. When the PSH flag is set in a packet, it indicates that the sender wants the data to be delivered to the receiver immediately.

* URG (Urgent): This flag is used to indicate that a data packet contains urgent data. When the URG flag is set in a packet, it indicates that the receiver should process this data before other data that may be in its buffer.

These flags are used in combination to control the flow of data between two devices in a TCP connection. For example, when a new connection is established, the SYN flag is set in the first packet, and the ACK flag is set in the second packet. When data is being transmitted, the ACK flag is set in each packet to acknowledge the receipt of the data. When the connection is closed, the FIN flag is set in the last packet.

## TCP connection work flow:
the SYN-SYN-ACK process. This process establishes a reliable and secure connection between the two devices. The steps involved in the three-way handshake are as follows:

Device A sends a packet with the SYN (Synchronize) flag set to initiate a connection with Device B.

Device B receives the packet and responds with a packet that has both the SYN and ACK (Acknowledgment) flags set, acknowledging the receipt of the SYN packet and requesting to start a connection with Device A.

Device A receives the packet with the SYN and ACK flags set and sends a packet with only the ACK flag set, acknowledging the receipt of the SYN-ACK packet and completing the three-way handshake.

Once the three-way handshake is completed, data can be transmitted between the two devices over the established TCP connection.

A TCP connection ends with a four-way handshake between the two devices, also known as the FIN-ACK process. This process terminates the connection in a orderly and reliable manner. The steps involved in the four-way handshake are as follows:

Device A sends a packet with the FIN (Finish) flag set to indicate that it wants to close the connection.

Device B receives the packet with the FIN flag set and sends a packet with the ACK flag set to acknowledge the receipt of the FIN packet.

Device B then sends a packet with the FIN flag set to indicate that it also wants to close the connection.

Device A receives the packet with the FIN flag set and sends a packet with the ACK flag set to acknowledge the receipt of the FIN packet and complete the four-way handshake.

The FIN-ACK process ensures that all data is transmitted and acknowledged before the connection is terminated, avoiding any data loss or corruption during the termination process.
